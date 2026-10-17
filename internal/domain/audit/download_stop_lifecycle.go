package audit

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

const DownloadStopWriterProtocol = "closed-download-stop/v1"
const DownloadStopHistoryLayout = "download-stop-history/v1"

// These are independently accepted installation qualification results. The
// adapter does not measure or infer a safe backup horizon or WAL footprint.
type DownloadStopLifecyclePolicy struct {
	RootID, InstallationID, StoreID, PolicyID, BackupProfileID, QualificationID  string
	PolicyDigest, BackupProfileDigest, QualificationDigest                       artifact.Digest
	Layout                                                                       string
	BackupHorizonSeconds, CleanupBudgetSeconds, ProofWindowSeconds               int64
	MaximumRowFootprintBytes, MaximumTransitionWALBytes, BackupCopies, WALCopies int64
	MaxPurgeLeases                                                               int64
}

func (p DownloadStopLifecyclePolicy) Valid() bool {
	for _, id := range []string{p.RootID, p.InstallationID, p.StoreID, p.PolicyID, p.BackupProfileID, p.QualificationID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return p.PolicyDigest != (artifact.Digest{}) && p.BackupProfileDigest != (artifact.Digest{}) && p.QualificationDigest != (artifact.Digest{}) && p.Layout == DownloadStopHistoryLayout && p.BackupHorizonSeconds >= 0 && p.BackupHorizonSeconds <= 316224000 && p.CleanupBudgetSeconds > 0 && p.CleanupBudgetSeconds <= 86400 && p.ProofWindowSeconds > 0 && p.ProofWindowSeconds <= 316224000 && p.MaximumRowFootprintBytes >= 128<<10 && p.MaximumRowFootprintBytes <= 16<<20 && p.MaximumTransitionWALBytes >= 128<<10 && p.MaximumTransitionWALBytes <= 64<<20 && p.BackupCopies >= 1 && p.BackupCopies <= 64 && p.WALCopies >= 1 && p.WALCopies <= 64 && p.MaxPurgeLeases >= 2 && p.MaxPurgeLeases <= 32
}

func (p DownloadStopLifecyclePolicy) SlotBacking() (cipher, keys, backup, wal int64) {
	// One original is deleted before its certificate is created. Five key
	// operations for the certificate (sign/wrap/self-open/two verifier opens),
	// plus the six original attempts and conservative headroom, are prepaid.
	return artifact.DownloadStopCipherLimit, 12, 2 * p.MaximumRowFootprintBytes * p.BackupCopies, 2 * p.MaximumTransitionWALBytes * p.WALCopies * (20 + 3*p.MaxPurgeLeases)
}

type DownloadStopLifecycleBinding struct {
	Protocol, RootID, DownloadID, AllocationID, IssuerEpoch                              string
	Policy                                                                               DownloadStopLifecyclePolicy
	ReservedAt, TransferUntil, HardDeleteBy                                              time.Time
	OriginalPurgeAt, CertificatePurgeAt, LiveRetireBy, HistoryReleaseAt, HistoryDeleteBy time.Time
}

func (b DownloadStopLifecycleBinding) Valid() bool {
	p := b.Policy
	for _, id := range []string{b.RootID, b.DownloadID, b.AllocationID, b.IssuerEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	for _, t := range []time.Time{b.ReservedAt, b.TransferUntil, b.HardDeleteBy, b.OriginalPurgeAt, b.CertificatePurgeAt, b.LiveRetireBy, b.HistoryReleaseAt, b.HistoryDeleteBy} {
		if !microTime(t) {
			return false
		}
	}
	if b.Protocol != DownloadStopWriterProtocol || !p.Valid() || p.RootID != b.RootID || !b.ReservedAt.Before(b.TransferUntil) || !b.TransferUntil.Before(b.HardDeleteBy) {
		return false
	}
	h, budget, proof := time.Duration(p.BackupHorizonSeconds)*time.Second, time.Duration(p.CleanupBudgetSeconds)*time.Second, time.Duration(p.ProofWindowSeconds)*time.Second
	return b.OriginalPurgeAt.Equal(b.HardDeleteBy.Add(-2*h-3*budget-proof)) && b.CertificatePurgeAt.Equal(b.HardDeleteBy.Add(-2*h-2*budget)) && b.LiveRetireBy.Equal(b.HardDeleteBy.Add(-2*h-budget)) && b.HistoryReleaseAt.Equal(b.HardDeleteBy.Add(-h-budget)) && b.HistoryDeleteBy.Equal(b.HardDeleteBy.Add(-h)) && b.OriginalPurgeAt.After(b.TransferUntil.Add(30*time.Second))
}

// Completion is emitted only by the one-use synchronous producer. SQL verifies
// the exact independently recorded claim and binding before retaining it.
type DownloadStopWriteCompletion struct {
	Protocol, RootID, DownloadID, StoreID, Phase string
	BindingDigest, RecordDigest                  artifact.Digest
	Receipt                                      Receipt
	StoredAt, ClosedAt                           time.Time
}

func DownloadStopCertificateKey(root, download string) string {
	return artifact.DownloadStopKey(root, download) + "/deletion-certificate"
}
func ValidDownloadStopReceipt(r Receipt, root, download, phase string) bool {
	key := artifact.DownloadStopKey(root, download)
	if phase == "certificate" {
		key = DownloadStopCertificateKey(root, download)
	} else if phase != "decision" {
		return false
	}
	copy := r
	copy.Key = OperationAuditKey(root, download, "intent")
	return r.Key == key && copy.ValidOperation(root, download, "intent")
}
func (c DownloadStopWriteCompletion) Valid(b DownloadStopLifecycleBinding, phase string, since, until time.Time) bool {
	return b.Valid() && c.Protocol == DownloadStopWriterProtocol && c.RootID == b.RootID && c.DownloadID == b.DownloadID && c.StoreID == b.Policy.StoreID && c.Phase == phase && c.BindingDigest != (artifact.Digest{}) && c.RecordDigest != (artifact.Digest{}) && ValidDownloadStopReceipt(c.Receipt, b.RootID, b.DownloadID, phase) && microTime(c.StoredAt) && microTime(c.ClosedAt) && !c.StoredAt.Before(since) && c.StoredAt.Before(until) && !c.ClosedAt.Before(c.StoredAt) && c.ClosedAt.Before(until)
}

// No actor, request key, filename or native content hash is included. Absent
// original objects are represented by the independently persisted unused fence,
// never inferred from an elapsed write interval.
type DownloadStopRetirement struct {
	RootID, DownloadID, StoreID, InstallationID, IssuerEpoch, Mode    string
	BindingDigest, ObjectsDigest, WritersDigest                       artifact.Digest
	PurgeFence                                                        int64
	PurgedAt, CertificateWriteUntil, CertificatePurgeAt, LiveRetireBy time.Time
}

func (r DownloadStopRetirement) Valid() bool {
	for _, id := range []string{r.RootID, r.DownloadID, r.StoreID, r.InstallationID, r.IssuerEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	for _, t := range []time.Time{r.PurgedAt, r.CertificateWriteUntil, r.CertificatePurgeAt, r.LiveRetireBy} {
		if !microTime(t) {
			return false
		}
	}
	return (r.Mode == "written" || r.Mode == "unused" || r.Mode == "unwritten") && r.BindingDigest != (artifact.Digest{}) && r.ObjectsDigest != (artifact.Digest{}) && r.WritersDigest != (artifact.Digest{}) && r.PurgeFence > 0 && r.PurgeFence <= 1<<60 && r.PurgedAt.Before(r.CertificateWriteUntil) && !r.CertificateWriteUntil.After(r.PurgedAt.Add(30*time.Second)) && r.CertificateWriteUntil.Before(r.CertificatePurgeAt) && r.CertificatePurgeAt.Before(r.LiveRetireBy)
}

type DownloadStopPurgeLease struct {
	RootID, DownloadID, StoreID, InstallationID, IssuerEpoch, Phase string
	BindingDigest, ObjectsDigest, WritersDigest                     artifact.Digest
	Fence                                                           int64
	StartedAt, Until                                                time.Time
}

func (l DownloadStopPurgeLease) Valid() bool {
	for _, id := range []string{l.RootID, l.DownloadID, l.StoreID, l.InstallationID, l.IssuerEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return (l.Phase == "original" || l.Phase == "terminal" || l.Phase == "overdue") && l.BindingDigest != (artifact.Digest{}) && l.ObjectsDigest != (artifact.Digest{}) && l.WritersDigest != (artifact.Digest{}) && l.Fence > 0 && l.Fence <= 1<<60 && microTime(l.StartedAt) && microTime(l.Until) && l.StartedAt.Before(l.Until) && !l.Until.After(l.StartedAt.Add(5*time.Second))
}

type DownloadStopPurgeResult struct {
	RootID, DownloadID, Phase                   string
	BindingDigest, ObjectsDigest, WritersDigest artifact.Digest
	Fence                                       int64
	PurgedAt, LeaseUntil                        time.Time
}

func (p DownloadStopPurgeResult) Valid(l DownloadStopPurgeLease) bool {
	return l.Valid() && p.RootID == l.RootID && p.DownloadID == l.DownloadID && p.Phase == l.Phase && p.BindingDigest == l.BindingDigest && p.ObjectsDigest == l.ObjectsDigest && p.WritersDigest == l.WritersDigest && p.Fence == l.Fence && microTime(p.PurgedAt) && !p.PurgedAt.Before(l.StartedAt) && p.PurgedAt.Before(l.Until) && p.LeaseUntil.Equal(l.Until)
}

type DownloadStopLifecycleSnapshot struct {
	Binding                     DownloadStopLifecycleBinding
	Decision                    *artifact.DownloadStopDecision
	Writer                      *DownloadStopWriteCompletion
	OriginalReceipt             *Receipt
	ClosedAt, OverdueSelectedAt time.Time
	Mode                        string
	Lease                       *DownloadStopPurgeLease
	Retirement                  *DownloadStopRetirement
	CertificateStarted          bool
	CertificateVerifyAttempts   int64
	CertificateWriter           *DownloadStopWriteCompletion
	CertificateReceipt          *Receipt
	Terminal                    *DownloadStopPurgeResult
	TerminalAcknowledged        bool
}
type DownloadStopHistoryKey struct {
	RootID, AllocationID string
	PolicyDigest         artifact.Digest
	ReleaseAt, DeleteBy  time.Time
}

func (k DownloadStopHistoryKey) Valid() bool {
	return authorization.UUID(k.RootID) && authorization.UUID(k.AllocationID) && k.PolicyDigest != (artifact.Digest{}) && microTime(k.ReleaseAt) && microTime(k.DeleteBy) && k.ReleaseAt.Before(k.DeleteBy)
}
