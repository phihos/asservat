package audit

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

const OperationWriterProtocol = "closed-operation-audit/v1"
const OperationHistoryLayout = "operation-audit-history/v1"
const OperationVerificationHistoryLayout = "operation-audit-history/v3"

// ShareOperationHistoryLayout additionally funds one share effect and its
// dependent row retirement. Earlier qualifications do not imply this coverage.
const ShareOperationHistoryLayout = "operation-audit-history/v4"

// ShareOperationBusinessWALBytes prepays one complete business effect, including
// the bounded 100-share mutation or its rollback, separately from audit phases.
// Every residual generation and WAL copy retains this allowance until release.
const ShareOperationBusinessWALBytes int64 = 8 << 20

func captureHistoryLayout(layout string) bool {
	return layout == CaptureOperationHistoryLayout || layout == ShareCaptureOperationHistoryLayout
}

func verificationHistoryLayout(layout string) bool {
	return layout == OperationVerificationHistoryLayout || layout == ShareOperationHistoryLayout ||
		layout == ProcessingReleaseHistoryLayout || captureHistoryLayout(layout)
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
	return authorization.UUID(q.ID) && q.Digest != (artifact.Digest{}) && (q.Layout == OperationHistoryLayout || q.Layout == OperationOverdueHistoryLayout || verificationHistoryLayout(q.Layout)) && q.MaximumRowFootprintBytes >= 128<<10 && q.MaximumRowFootprintBytes <= 16<<20 && q.MaximumTransitionWALBytes >= 128<<10 && q.MaximumTransitionWALBytes <= 64<<20 && q.BackupCopies >= 1 && q.BackupCopies <= 64 && q.WALCopies >= 1 && q.WALCopies <= 64
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
	} else if q.Layout == ShareOperationHistoryLayout {
		// Existing verifier lifecycle plus paid effect consumption, business
		// mutation and dependent share retirement. Full transaction bounds
		// must include the closed 100-share revoke-all case.
		transitions = 24
	} else if q.Layout == ShareCaptureOperationHistoryLayout {
		// Capture admission/publication plus the immutable share dependency
		// and its removal during the creating operation's finalization.
		transitions = 34
	} else if q.Layout == CaptureOperationHistoryLayout {
		// Pair/lifecycle plus immutable admission, binding, two reads per phase,
		// acknowledgement and bounded dependent row retirement.
		transitions = 32
	} else if q.Layout == ProcessingReleaseHistoryLayout {
		// Separately qualified release account/business and existing lifecycle writes.
		transitions = 32
	}
	business := int64(0)
	if q.Layout == ShareOperationHistoryLayout {
		business = ShareOperationBusinessWALBytes
	}
	return 2 * q.MaximumRowFootprintBytes * q.BackupCopies, 2 * q.WALCopies * (q.MaximumTransitionWALBytes*(transitions+3*leases) + business)
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
	if p.BackupHorizonSeconds > 0 || p.History != nil && verificationHistoryLayout(p.History.Layout) {
		if p.History == nil || !p.History.Valid() || (!verificationHistoryLayout(p.History.Layout) && ((p.OverdueTerminal == "" && p.History.Layout != OperationHistoryLayout) || (p.OverdueTerminal != "" && p.History.Layout != OperationOverdueHistoryLayout))) {
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
	return authorization.UUID(p.RootID) && p.historyLaneValid() && authorization.UUID(p.InstallationID) && authorization.UUID(p.StoreID) && authorization.UUID(p.PolicyID) && authorization.UUID(p.BackupProfileID) && p.PolicyDigest != (artifact.Digest{}) && p.BackupProfileDigest != (artifact.Digest{}) && p.BackingRevision > 0 && p.BackingRevision <= 1<<60 && p.MetadataSlots > 0 && p.MetadataSlots <= 1000000000000 && p.BackupHorizonSeconds >= 0 && p.BackupHorizonSeconds <= 316224000 && p.CleanupBudgetSeconds > 0 && p.CleanupBudgetSeconds <= 86400 && p.ProofWindowSeconds > 0 && p.ProofWindowSeconds <= 316224000 && p.BackupReservedBytes >= 0 && p.WALReservedBytes >= 0 && (p.BackupHorizonSeconds == 0 || p.BackupReservedBytes > 0 && p.WALReservedBytes > 0) && microTime(p.ValidUntil)
}

func (p OperationLifecyclePolicy) historyLaneValid() bool {
	switch p.Lane {
	case "normal", "resolution":
		return p.History == nil || p.History.Layout == OperationHistoryLayout || p.History.Layout == OperationOverdueHistoryLayout || p.History.Layout == OperationVerificationHistoryLayout || p.History.Layout == ShareOperationHistoryLayout
	case "capture":
		return p.History != nil && captureHistoryLayout(p.History.Layout)
	case "processing":
		return p.History != nil && p.History.Layout == ProcessingReleaseHistoryLayout
	}
	return false
}

// CertificateVerificationBacked selects new admission, including H=0. Valid
// intentionally still reads historical bindings; it never upgrades them.
func (p OperationLifecyclePolicy) CertificateVerificationBacked() bool {
	return p.Valid() && p.History != nil && verificationHistoryLayout(p.History.Layout)
}

// SharingBacked identifies a separately qualified share-business graph, not
// permission to share or a promotion of a historical audit record.
func (p OperationLifecyclePolicy) SharingBacked() bool {
	return p.Valid() && p.History != nil && (p.History.Layout == ShareOperationHistoryLayout || p.History.Layout == ShareCaptureOperationHistoryLayout)
}

func microTime(t time.Time) bool { return !t.IsZero() && t.Nanosecond()%1000 == 0 }
