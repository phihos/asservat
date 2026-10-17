package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func TestProcessingBackingIncludesRetainedFailedInitialization(t *testing.T) {
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	b := ProcessingBacking{RootID: processingID(1), InstallationID: processingID(2), PolicyID: processingID(3), BackupIdentity: processingID(4), PolicyDigest: artifact.Digest{1}, BackupDigest: artifact.Digest{2}, History: ProcessingHistoryQualification{Format: ProcessingHistoryFormat, ID: processingID(5), Digest: artifact.Digest{3}, RowBytes: 16 << 10, TransitionWALBytes: 64 << 10, BackupCopies: 2, WALCopies: 2}, MaxCaptures: 1, MaxRules: 1, MaxRootTransitions: 64, BackupHorizonSeconds: 2, CleanupSeconds: 5, ValidUntil: n, RetireBy: n.Add(9 * time.Second)}
	// Even with no applied completeness decision, up to64 immutable attempted
	// initializations can remain. Counting only one root silently underbacks them.
	b.BackupBytes = 2 * (1 + b.MaxCaptures + 17*b.MaxRules) * b.History.RowBytes * b.History.BackupCopies
	b.WALBytes = (b.MaxRootTransitions + 2*b.MaxCaptures + 130*b.MaxRules) * b.History.TransitionWALBytes * b.History.WALCopies
	if b.Valid() {
		t.Fatal("retained failed initialization rows were unbacked")
	}
	var ok bool
	b.BackupBytes, b.WALBytes, ok = b.RequiredBytes()
	if !ok || !b.Valid() {
		t.Fatal("complete finite backing rejected")
	}
	b.BackupBytes--
	if b.Valid() {
		t.Fatal("short backup reservation accepted")
	}
}
