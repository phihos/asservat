package execution

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func TestAPIStartNeverAcceptsNodeIdentityOrLargerBudget(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	n := time.Date(2026, 10, 11, 1, 0, 0, 0, time.UTC)
	b := Binding{ExecutionClass: artifact.ContextAPIExecution, ExecutorPodUID: id, ExecutorAccountUID: id, OperationID: id, CaptureID: id, ActionID: "pod-status", AttemptID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, CollectorEpoch: id, ScopeDigest: artifact.Digest{1}, AuthorityDigest: artifact.Digest{2}, BudgetDigest: artifact.Digest{3}, AuditDigest: artifact.Digest{4}, NativeBytes: 4096, NotBefore: n, NotAfter: n.Add(5 * time.Second)}
	if !b.Valid() {
		t.Fatal("invalid fixture")
	}
	for _, change := range []func(*Binding){func(b *Binding) { b.NodeUID = id }, func(b *Binding) { b.NodeBootID = id }, func(b *Binding) { b.ExecutorPodUID = "" }, func(b *Binding) { b.NativeBytes++ }, func(b *Binding) { b.NotAfter = b.NotBefore.Add(6 * time.Second) }, func(b *Binding) { b.ActionID = "command" }, func(b *Binding) { b.ExecutionClass = artifact.ContextNodeExecution }} {
		x := b
		change(&x)
		if x.Valid() {
			t.Fatal("mixed execution class or wider acquisition accepted")
		}
	}
}
