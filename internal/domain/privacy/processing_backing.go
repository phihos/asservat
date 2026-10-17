package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"math"
	"time"
)

const ProcessingHistoryFormat = "context-processing-history/v1"
const MaxProcessingChanges = 16

// These are independently accepted backend qualification results, not runtime
// estimates. The footprint includes a complete per-capture lineage row, rule,
// immutable decision/idempotency rows, indexes and full transaction WAL. Audit
// object/cryptographic costs retain their separate existing operation backing.
type ProcessingHistoryQualification struct {
	Format, ID                                            string
	Digest                                                artifact.Digest
	RowBytes, TransitionWALBytes, BackupCopies, WALCopies int64
}

func (q ProcessingHistoryQualification) Valid() bool {
	return q.Format == ProcessingHistoryFormat && authorization.UUID(q.ID) && q.Digest != (artifact.Digest{}) && q.RowBytes >= 16<<10 && q.RowBytes <= 16<<20 && q.TransitionWALBytes >= 64<<10 && q.TransitionWALBytes <= 64<<20 && q.BackupCopies >= 1 && q.BackupCopies <= 64 && q.WALCopies >= 1 && q.WALCopies <= 64
}

type ProcessingBacking struct {
	RootID, InstallationID, PolicyID, BackupIdentity string
	PolicyDigest, BackupDigest                       artifact.Digest
	History                                          ProcessingHistoryQualification
	MaxCaptures, MaxRules, MaxRootTransitions        int64
	BackupBytes, WALBytes                            int64
	BackupHorizonSeconds, CleanupSeconds             int64
	ValidUntil, RetireBy                             time.Time
}

func processingProduct(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || a != 0 && b > math.MaxInt64/a {
		return 0, false
	}
	return a * b, true
}
func (b ProcessingBacking) RequiredBytes() (backup, wal int64, ok bool) {
	if !b.History.Valid() || b.MaxCaptures < 1 || b.MaxCaptures > 1000000 || b.MaxRules < 1 || b.MaxRules > MaxProcessingRules || b.MaxRootTransitions < 8 || b.MaxRootTransitions > 65536 {
		return 0, 0, false
	}
	// One root plus at most one immutable initialization decision per root
	// transition, one lineage row per capture, and one rule plus at most
	// sixteen decisions per rule. Failed initialization remains retained too.
	// Keep both live and residual generations.
	rows := int64(1) + b.MaxRootTransitions + b.MaxCaptures + (1+MaxProcessingChanges)*b.MaxRules
	x, ok := processingProduct(2*rows, b.History.RowBytes)
	if !ok {
		return 0, 0, false
	}
	backup, ok = processingProduct(x, b.History.BackupCopies)
	if !ok {
		return 0, 0, false
	}
	// Up to four writes per root initialization decision, two per lineage insertion, and
	// eight per rule decision cover reserve/apply/ack/CAS rollback accounting.
	transitions := 4*b.MaxRootTransitions + 2*b.MaxCaptures + (2+8*MaxProcessingChanges)*b.MaxRules
	x, ok = processingProduct(transitions, b.History.TransitionWALBytes)
	if !ok {
		return 0, 0, false
	}
	wal, ok = processingProduct(x, b.History.WALCopies)
	return backup, wal, ok
}
func (b ProcessingBacking) Valid() bool {
	if !authorization.UUID(b.RootID) || !authorization.UUID(b.InstallationID) || !authorization.UUID(b.PolicyID) || !authorization.UUID(b.BackupIdentity) || b.PolicyDigest == (artifact.Digest{}) || b.BackupDigest == (artifact.Digest{}) || b.BackupHorizonSeconds < 0 || b.BackupHorizonSeconds > 316224000 || b.CleanupSeconds < 1 || b.CleanupSeconds > 86400 || b.ValidUntil.IsZero() || !b.RetireBy.Equal(b.ValidUntil.Add(time.Duration(2*b.BackupHorizonSeconds+b.CleanupSeconds)*time.Second)) {
		return false
	}
	x, y, ok := b.RequiredBytes()
	return ok && b.BackupBytes >= x && b.WALBytes >= y
}
