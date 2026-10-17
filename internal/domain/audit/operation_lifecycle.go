package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"time"
)

const OperationWriterProtocol = "closed-operation-audit/v1"
const OperationHistoryLayout = "operation-audit-history/v1"
const OperationVerificationHistoryLayout = "operation-audit-history/v3"

// This distinct private qualification includes retained connector source/process/
// certificate dependencies; a public v3 result is never automatically sufficient.
const ConnectorOperationHistoryLayout = "connector-operation-history/v1"

// V2 additionally backs the immutable restrictive ticket, complete reservation
// set, one-use consumption and retirement closures. V1 evidence does not
// qualify this shape.
const ConnectorRetirementHistoryLayout = "connector-operation-history/v2"

func connectorHistoryLayout(layout string) bool {
	return layout == ConnectorOperationHistoryLayout || layout == ConnectorRetirementHistoryLayout
}

const ProcessingReleaseHistoryLayout = "processing-release-history/v1"
const OperationOverdueHistoryLayout = "operation-audit-history/v2"
const OperationOverdueTerminal = "overdue-original/v1"

// This is an accepted qualification result, not an estimate or a caller's
// capacity declaration. Bounds include all heap/TOAST/index pages and the full
// transaction, including rollback/row-lock WAL within the qualified attempt
// envelope. A production qualification/source producer remains separate.
type OperationHistoryQualification struct {
	ID                                                  string
	Digest                                              artifact.Digest
	Layout                                              string
	MaximumRowFootprintBytes, MaximumTransitionWALBytes int64
	BackupCopies, WALCopies                             int64
}

func (q OperationHistoryQualification) Valid() bool {
	return authorization.UUID(q.ID) && q.Digest != (artifact.Digest{}) && (q.Layout == OperationHistoryLayout || q.Layout == OperationOverdueHistoryLayout || q.Layout == OperationVerificationHistoryLayout || connectorHistoryLayout(q.Layout) || q.Layout == ProcessingReleaseHistoryLayout || q.Layout == CaptureOperationHistoryLayout) && (!connectorHistoryLayout(q.Layout) || q.MaximumRowFootprintBytes >= 1<<20) && q.MaximumRowFootprintBytes >= 128<<10 && q.MaximumRowFootprintBytes <= 16<<20 && q.MaximumTransitionWALBytes >= 128<<10 && q.MaximumTransitionWALBytes <= 64<<20 && q.BackupCopies >= 1 && q.BackupCopies <= 64 && q.WALCopies >= 1 && q.WALCopies <= 64
}
func (q OperationHistoryQualification) SlotBacking(leases int64) (backup, wal int64) {
	// At most two residual generations overlap; every reuse waits through H.
	// The fixed phase writes and three writes per finite purge lease are covered.
	transitions := int64(16)
	if q.Layout == OperationOverdueHistoryLayout {
		transitions += 3
	} else if q.Layout == OperationVerificationHistoryLayout {
		// Includes the optional overdue branch and two irreversible verifier claims.
		transitions += 5
	} else if q.Layout == CaptureOperationHistoryLayout {
		// Pair/lifecycle plus immutable admission, binding, two reads per phase,
		// acknowledgement and bounded dependent row retirement.
		transitions = 32
	} else if q.Layout == ProcessingReleaseHistoryLayout {
		// Separately qualified release account/business and existing lifecycle writes.
		transitions = 32
	} else if q.Layout == ConnectorRetirementHistoryLayout {
		// Eight additional bounded ticket reserve/bind/consume-or-close/retire
		// writes; the independently accepted WAL bound includes full multi-peer
		// transactions, not only one row. No qualification is inferred here.
		transitions = 40
	} else if q.Layout == ConnectorOperationHistoryLayout {
		// Existing 21 lifecycle transitions plus at most eleven source/business
		// admission, acceptance, signing, activation and dependency retirements.
		// SQL49 enforces that graph; actual transaction cost needs its own test.
		transitions = 32
	}
	return 2 * q.MaximumRowFootprintBytes * q.BackupCopies, 2 * q.MaximumTransitionWALBytes * q.WALCopies * (transitions + 3*leases)
}

// These facts come only from accepted protected installation composition. They
// are neither public request fields nor a source-acceptance implementation.
type OperationLifecyclePolicy struct {
	RootID, Lane, InstallationID, StoreID, PolicyID, BackupProfileID      string
	PolicyDigest, BackupProfileDigest                                     artifact.Digest
	BackingRevision, MetadataSlots, BackupReservedBytes, WALReservedBytes int64
	BackupHorizonSeconds, CleanupBudgetSeconds, ProofWindowSeconds        int64
	ValidUntil                                                            time.Time
	MaxPurgeLeases                                                        int64
	History                                                               *OperationHistoryQualification `json:",omitempty"`
	OverdueTerminal                                                       string                         `json:",omitempty"`
}

func (p OperationLifecyclePolicy) Valid() bool {
	if p.OverdueTerminal != "" && p.OverdueTerminal != OperationOverdueTerminal {
		return false
	}
	if p.MaxPurgeLeases < 2 || p.MaxPurgeLeases > 32 {
		return false
	}
	if p.BackupHorizonSeconds > 0 || p.History != nil && (p.History.Layout == OperationVerificationHistoryLayout || connectorHistoryLayout(p.History.Layout) || p.History.Layout == ProcessingReleaseHistoryLayout || p.History.Layout == CaptureOperationHistoryLayout) {
		if p.History == nil || !p.History.Valid() || (p.History.Layout != OperationVerificationHistoryLayout && !connectorHistoryLayout(p.History.Layout) && p.History.Layout != ProcessingReleaseHistoryLayout && p.History.Layout != CaptureOperationHistoryLayout && ((p.OverdueTerminal == "" && p.History.Layout != OperationHistoryLayout) || (p.OverdueTerminal != "" && p.History.Layout != OperationOverdueHistoryLayout))) {
			return false
		}
		b, w := p.History.SlotBacking(p.MaxPurgeLeases)
		// Division avoids overflow and tests actual required per-slot backing.
		if p.MetadataSlots <= 0 || p.BackupReservedBytes/p.MetadataSlots < b || p.WALReservedBytes/p.MetadataSlots < w {
			return false
		}
	} else if p.History != nil {
		return false
	}
	return authorization.UUID(p.RootID) && ((p.Lane == "normal" || p.Lane == "resolution") && (p.History == nil || !connectorHistoryLayout(p.History.Layout) && p.History.Layout != ProcessingReleaseHistoryLayout && p.History.Layout != CaptureOperationHistoryLayout) || p.Lane == "capture" && p.History != nil && p.History.Layout == CaptureOperationHistoryLayout || p.Lane == "processing" && p.History != nil && p.History.Layout == ProcessingReleaseHistoryLayout || p.Lane == "identity" && p.History != nil && connectorHistoryLayout(p.History.Layout)) && authorization.UUID(p.InstallationID) && authorization.UUID(p.StoreID) && authorization.UUID(p.PolicyID) && authorization.UUID(p.BackupProfileID) && p.PolicyDigest != (artifact.Digest{}) && p.BackupProfileDigest != (artifact.Digest{}) && p.BackingRevision > 0 && p.BackingRevision <= 1<<60 && p.MetadataSlots > 0 && p.MetadataSlots <= 1000000000000 && p.BackupHorizonSeconds >= 0 && p.BackupHorizonSeconds <= 316224000 && p.CleanupBudgetSeconds > 0 && p.CleanupBudgetSeconds <= 86400 && p.ProofWindowSeconds > 0 && p.ProofWindowSeconds <= 316224000 && p.BackupReservedBytes >= 0 && p.WALReservedBytes >= 0 && (p.BackupHorizonSeconds == 0 || p.BackupReservedBytes > 0 && p.WALReservedBytes > 0) && microTime(p.ValidUntil)
}

// CertificateVerificationBacked selects new admission, including H=0. Valid
// intentionally still reads historical bindings; it never upgrades them.
func (p OperationLifecyclePolicy) CertificateVerificationBacked() bool {
	return p.Valid() && p.History != nil && (p.History.Layout == OperationVerificationHistoryLayout || connectorHistoryLayout(p.History.Layout) || p.History.Layout == ProcessingReleaseHistoryLayout || p.History.Layout == CaptureOperationHistoryLayout)
}

type OperationLifecycleBinding struct {
	Protocol                                          string
	Policy                                            OperationLifecyclePolicy
	OriginalPurgeAt, CertificatePurgeAt, LiveRetireBy time.Time
	HistoryReleaseAt, HistoryDeleteBy                 time.Time
}

func (b OperationLifecycleBinding) Valid(in OperationIntent) bool {
	p := b.Policy
	if b.Protocol != OperationWriterProtocol || !p.Valid() || p.RootID != in.RootID || p.Lane != OperationLane(in.Name) || !in.CreatedAt.Before(p.ValidUntil) {
		return false
	}
	budget := time.Duration(p.CleanupBudgetSeconds) * time.Second
	live := in.RetainUntil.Add(-2*time.Duration(p.BackupHorizonSeconds)*time.Second - budget)
	cert := live.Add(-budget)
	original := cert.Add(-time.Duration(p.ProofWindowSeconds)*time.Second - budget)
	return microTime(b.OriginalPurgeAt) && microTime(b.CertificatePurgeAt) && microTime(b.LiveRetireBy) && b.OriginalPurgeAt.Equal(original) && b.CertificatePurgeAt.Equal(cert) && b.LiveRetireBy.Equal(live) && original.After(in.WriteUntil) && b.HistoryReleaseAt.Equal(in.RetainUntil.Add(-time.Duration(p.BackupHorizonSeconds)*time.Second-budget)) && b.HistoryDeleteBy.Equal(in.RetainUntil.Add(-time.Duration(p.BackupHorizonSeconds)*time.Second))
}
func microTime(t time.Time) bool { return !t.IsZero() && t.Nanosecond()%1000 == 0 }

// A completion can only be issued by the actual one-use producer after a
// successful PUT response, independent exact verification and joined closure.
// It is not reconstructed from existence, a receipt or elapsed time.
type OperationWriteCompletion struct {
	Protocol, RootID, OperationID, StoreID, Phase string
	RecordDigest                                  artifact.Digest
	Receipt                                       Receipt
	StoredAt, ClosedAt                            time.Time
}

func (c OperationWriteCompletion) Valid(root, id, store, phase string, since, until time.Time) bool {
	return c.Protocol == OperationWriterProtocol && c.RootID == root && c.OperationID == id && c.StoreID == store && c.Phase == phase && c.RecordDigest != (artifact.Digest{}) && validLifecycleReceipt(c.Receipt, root, id, phase) && microTime(c.StoredAt) && microTime(c.ClosedAt) && !c.StoredAt.Before(since) && c.StoredAt.Before(until) && !c.ClosedAt.Before(c.StoredAt) && c.ClosedAt.Before(until)
}
func validLifecycleReceipt(r Receipt, root, id, phase string) bool {
	if phase == "intent" || phase == "outcome" {
		return r.ValidOperation(root, id, phase)
	}
	if phase != "deletion-certificate" {
		return false
	}
	// Keep exactly the same bounded receipt validation without broadening the
	// ordinary two-phase OperationObjects interface to accept arbitrary keys.
	copy := r
	copy.Key = OperationAuditKey(root, id, "intent")
	return r.Key == OperationAuditKey(root, id, phase) && copy.ValidOperation(root, id, "intent")
}
func (r Receipt) ValidOperationRetirement(root, id string) bool {
	return validLifecycleReceipt(r, root, id, "deletion-certificate")
}

// OperationRetirement has no actor/account/input/output identifiers or digests.
// Its ciphertext/writer hashes refer only to the registered encrypted objects.
type OperationRetirement struct {
	RootID, OperationID, StoreID, InstallationID, IssuerEpoch         string
	PostmasterAt                                                      time.Time
	DatabaseOID                                                       uint32
	ObjectsDigest, WritersDigest                                      artifact.Digest
	PurgeFence                                                        int64
	PurgedAt, CertificateWriteUntil, CertificatePurgeAt, LiveRetireBy time.Time
}

func (r OperationRetirement) Valid() bool {
	for _, id := range []string{r.RootID, r.OperationID, r.StoreID, r.InstallationID, r.IssuerEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	for _, t := range []time.Time{r.PostmasterAt, r.PurgedAt, r.CertificateWriteUntil, r.CertificatePurgeAt, r.LiveRetireBy} {
		if !microTime(t) {
			return false
		}
	}
	return r.DatabaseOID > 0 && r.ObjectsDigest != (artifact.Digest{}) && r.WritersDigest != (artifact.Digest{}) && r.PurgeFence > 0 && r.PurgedAt.Before(r.CertificateWriteUntil) && !r.CertificateWriteUntil.After(r.PurgedAt.Add(30*time.Second)) && !r.CertificateWriteUntil.After(r.CertificatePurgeAt) && r.CertificatePurgeAt.Before(r.LiveRetireBy)
}

type OperationTerminalPurge struct {
	RootID, OperationID                 string
	RetirementDigest, CertificateDigest artifact.Digest
	Fence                               int64
	PurgedAt, LeaseUntil                time.Time
}

func (r OperationTerminalPurge) Valid() bool {
	return authorization.UUID(r.RootID) && authorization.UUID(r.OperationID) && r.RetirementDigest != (artifact.Digest{}) && r.CertificateDigest != (artifact.Digest{}) && r.Fence > 0 && microTime(r.PurgedAt) && microTime(r.LeaseUntil) && r.PurgedAt.Before(r.LeaseUntil)
}

// A lease is a finite exact backend operation, never a replacement writer proof.
type OperationPurgeLease struct {
	RootID, OperationID, StoreID, InstallationID, IssuerEpoch, Phase string
	PostmasterAt                                                     time.Time
	DatabaseOID                                                      uint32
	ObjectsDigest, WritersDigest                                     artifact.Digest
	Fence                                                            int64
	StartedAt, Until                                                 time.Time
}

func (l OperationPurgeLease) Valid() bool {
	for _, id := range []string{l.RootID, l.OperationID, l.StoreID, l.InstallationID, l.IssuerEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return (l.Phase == "original" || l.Phase == "terminal" || l.Phase == "overdueOriginal") && l.DatabaseOID > 0 && microTime(l.PostmasterAt) && microTime(l.StartedAt) && microTime(l.Until) && l.StartedAt.Before(l.Until) && !l.Until.After(l.StartedAt.Add(5*time.Second)) && l.Fence > 0 && l.Fence <= 1<<60 && l.ObjectsDigest != (artifact.Digest{}) && l.WritersDigest != (artifact.Digest{})
}

type OperationLifecycleSnapshot struct {
	OverdueSelectedAt           time.Time
	OverduePurge                *OperationOverduePurge
	Intent                      OperationIntent
	IntentWriter, OutcomeWriter *OperationWriteCompletion
	Lease                       *OperationPurgeLease
	Retirement                  *OperationRetirement
	CertificateVerifyAttempts   int64
	CertificateStarted          bool
	CertificateWriter           *OperationWriteCompletion
	CertificateReceipt          *Receipt
	Terminal                    *OperationTerminalPurge
	TerminalAcknowledged        bool
}

// A cooling key intentionally retains principal correlation until its finite
// drain; operation/trace/case identities are absent. It is private worker state.
type OperationHistoryKey struct {
	RootID, Lane        string
	PrincipalDigest     artifact.Digest
	ReleaseAt, DeleteBy time.Time
}

func (k OperationHistoryKey) Valid() bool {
	return authorization.UUID(k.RootID) && (k.Lane == "normal" || k.Lane == "resolution" || k.Lane == "identity" || k.Lane == "processing" || k.Lane == "capture") && k.PrincipalDigest != (artifact.Digest{}) && microTime(k.ReleaseAt) && microTime(k.DeleteBy) && k.ReleaseAt.Before(k.DeleteBy)
}

type OperationHistoryRelease struct {
	Records int64
	Overdue bool
}

// An overdue result acknowledges current absence after an irreversible
// no-certificate fence. It never fabricates a certificate or its proof window.
type OperationOverduePurge struct {
	RootID, OperationID, Mode                   string
	BindingDigest, ObjectsDigest, WritersDigest artifact.Digest
	Fence                                       int64
	SelectedAt, PurgedAt, LeaseUntil            time.Time
}

func (p OperationOverduePurge) Valid() bool {
	return authorization.UUID(p.RootID) && authorization.UUID(p.OperationID) && p.Mode == OperationOverdueTerminal && p.BindingDigest != (artifact.Digest{}) && p.ObjectsDigest != (artifact.Digest{}) && p.WritersDigest != (artifact.Digest{}) && p.Fence > 0 && microTime(p.SelectedAt) && microTime(p.PurgedAt) && microTime(p.LeaseUntil) && !p.PurgedAt.Before(p.SelectedAt) && p.PurgedAt.Before(p.LeaseUntil)
}
