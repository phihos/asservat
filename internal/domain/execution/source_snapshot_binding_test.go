package execution

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func TestAPIRecorderBindingCarriesBoundedSnapshotOutputCeiling(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	id := "00000000-0000-4000-8000-000000000001"
	b := Binding{ExecutionClass: artifact.ContextAPIExecution, ExecutorPodUID: id, ExecutorAccountUID: id, OperationID: id, CaptureID: id, ActionID: "a000000000000000000000001", AttemptID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, CollectorEpoch: id, ScopeDigest: artifact.Digest{1}, AuthorityDigest: artifact.Digest{2}, BudgetDigest: artifact.Digest{3}, AuditDigest: artifact.Digest{4}, NativeBytes: artifact.RecordingNativeLimit, NotBefore: now, NotAfter: now.Add(5 * time.Second)}
	if !b.Valid() {
		t.Fatal("existing finite recorder binding baseline")
	}
	b.NativeBytes = 64 << 10
	if !b.Valid() {
		t.Fatal("valid typed64KiB snapshot registration cannot pass existing local effect binding")
	}
	for name, bytes := range map[string]int64{"zero": 0, "negative": -1, "over8MiB": artifact.RecordingNativeLimit + 1} {
		t.Run(name, func(t *testing.T) {
			changed := b
			changed.NativeBytes = bytes
			if changed.Valid() {
				t.Fatal("invalid bounded output ceiling accepted", bytes)
			}
		})
	}
	b.ActionID = "pod-status"
	if b.Valid() {
		t.Fatal("bounded recorder ceiling widened exact pod-status bytes")
	}
	b.NativeBytes = artifact.MaxContextBytes
	if !b.Valid() {
		t.Fatal("original pod-status binding changed")
	}
}
