package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func stopLifecycleBinding() DownloadStopLifecycleBinding {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	id := "11111111-1111-4111-8111-111111111111"
	p := DownloadStopLifecyclePolicy{RootID: id, InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, QualificationID: id, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, QualificationDigest: artifact.Digest{3}, Layout: DownloadStopHistoryLayout, BackupHorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1, MaxPurgeLeases: 4}
	d := now.Add(24 * time.Hour)
	return DownloadStopLifecycleBinding{Protocol: DownloadStopWriterProtocol, RootID: id, DownloadID: id, AllocationID: id, IssuerEpoch: id, Policy: p, ReservedAt: now, TransferUntil: now.Add(time.Hour), HardDeleteBy: d, OriginalPurgeAt: d.Add(-2*time.Hour - 4*time.Minute), CertificatePurgeAt: d.Add(-2*time.Hour - 2*time.Minute), LiveRetireBy: d.Add(-2*time.Hour - time.Minute), HistoryReleaseAt: d.Add(-time.Hour - time.Minute), HistoryDeleteBy: d.Add(-time.Hour)}
}
func TestDownloadStopLifecycleDatesAndQualifiedBacking(t *testing.T) {
	b := stopLifecycleBinding()
	if !b.Valid() {
		t.Fatal("invalid fixture")
	}
	for _, change := range []func(*DownloadStopLifecycleBinding){func(b *DownloadStopLifecycleBinding) { b.OriginalPurgeAt = b.OriginalPurgeAt.Add(time.Microsecond) }, func(b *DownloadStopLifecycleBinding) { b.Policy.BackupHorizonSeconds = 0 }, func(b *DownloadStopLifecycleBinding) { b.TransferUntil = b.OriginalPurgeAt.Add(-30 * time.Second) }, func(b *DownloadStopLifecycleBinding) { b.Protocol = "prepaid-download-stop/v1" }, func(b *DownloadStopLifecycleBinding) { b.Policy.QualificationDigest = artifact.Digest{} }} {
		v := b
		change(&v)
		if v.Valid() {
			t.Fatal("sliding, unqualified or legacy binding accepted")
		}
	}
	c, k, backup, wal := b.Policy.SlotBacking()
	if c != 65536 || k != 12 || backup != 2*131072 || wal != 2*131072*(20+3*4) {
		t.Fatal("incomplete original/certificate/residual backing", c, k, backup, wal)
	}
}
func TestDownloadStopCompletionCannotBeAReceiptOrDifferentPhase(t *testing.T) {
	b := stopLifecycleBinding()
	since, until := b.ReservedAt, b.ReservedAt.Add(30*time.Second)
	c := DownloadStopWriteCompletion{Protocol: DownloadStopWriterProtocol, RootID: b.RootID, DownloadID: b.DownloadID, StoreID: b.Policy.StoreID, Phase: "decision", BindingDigest: artifact.Digest{1}, RecordDigest: artifact.Digest{2}, Receipt: Receipt{Key: artifact.DownloadStopKey(b.RootID, b.DownloadID), ETag: "exact", Bytes: 10, SHA256: artifact.Digest{3}}, StoredAt: since.Add(time.Second), ClosedAt: since.Add(2 * time.Second)}
	if !c.Valid(b, "decision", since, until) {
		t.Fatal("positive completion rejected")
	}
	for _, change := range []func(*DownloadStopWriteCompletion){func(c *DownloadStopWriteCompletion) { c.ClosedAt = time.Time{} }, func(c *DownloadStopWriteCompletion) { c.ClosedAt = until }, func(c *DownloadStopWriteCompletion) { c.Phase = "certificate" }, func(c *DownloadStopWriteCompletion) {
		c.Receipt.Key = OperationAuditKey(b.RootID, b.DownloadID, "intent")
	}} {
		v := c
		change(&v)
		if v.Valid(b, "decision", since, until) {
			t.Fatal("receipt or foreign purpose became completion")
		}
	}
}
