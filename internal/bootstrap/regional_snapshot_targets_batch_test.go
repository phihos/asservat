package bootstrap

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/targets"
)

func TestSnapshotBatchRetainsDeletedPodAndRefusesWholeUnavailableSelection(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Microsecond)
	clock := &packetRingClock{at: start.Add(3 * time.Second)}
	permit := sourceOwnerPermit(start)
	binding := permit.Binding
	request := targets.Request{ClusterID: binding.PodUID, Namespace: configuration.NamespaceRef{Name: "app", UID: binding.PodUID}, Workload: configuration.WorkloadRef{Kind: "Pod", Name: "old-pod", UID: binding.PodUID}, PodName: "old-pod", PodUID: binding.PodUID}
	original := targets.SourceSnapshotTarget{Request: request, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: binding.PodUID, Name: "old-pod", UID: binding.PodUID}, NodeUID: binding.NodeUID, BootID: binding.BootID, CollectorPodUID: binding.CollectorPodUID, CollectorEpoch: binding.CollectorEpoch, SourceID: binding.SourceID, Fence: binding.Fence, BindingDigest: [32]byte{1}}
	second := original
	second.SourceID = "22222222-2222-4222-8222-222222222222"
	status := collector.SourceStatus{SourceID: original.SourceID, Fence: original.Fence, IssuedAt: permit.IssuedAt, LeafUntil: permit.LeafUntil, Credit: permit.Credit, Stopped: true, SourceStoppedAt: start.Add(time.Second), SnapshotUntil: permit.LeafUntil}
	other := status
	other.SourceID = second.SourceID
	registry := &retainedSourceRegistry{view: delivery.NodeView{Identity: collector.Identity{NodeUID: binding.NodeUID, BootID: binding.BootID, PodUID: binding.CollectorPodUID, Epoch: binding.CollectorEpoch}, Current: true, Report: &collector.Report{ObservedAt: start.Add(2 * time.Second), Sources: []collector.SourceStatus{status, other}}}}
	// No PodTargets: neither a deleted target nor its namesake can be read.
	resolver := reportedTargets{recordings: &ConnectorRecordings{nodes: registry, now: clock.now}}
	ctx, cancel := context.WithDeadline(t.Context(), start.Add(time.Minute))
	defer cancel()
	selected := []targets.SourceSnapshotTarget{original, second}
	got, err := resolver.ResolveSourceSnapshots(ctx, selected)
	if err != nil || len(got) != 2 || got[1].Original != second || !got[0].State.Stopped || !got[1].ReportedAt.Equal(registry.view.Report.ObservedAt) {
		t.Fatal("retained same-Pod action sources lost", got, err)
	}
	registry.view.Report.Sources = registry.view.Report.Sources[:1]
	if got, err = resolver.ResolveSourceSnapshots(ctx, selected); err == nil || len(got) != 0 {
		t.Fatal("missing source silently dropped", len(got), err)
	}
	registry.view.Report.Sources = append(registry.view.Report.Sources, other)
	selected[1].BootID = "33333333-3333-4333-8333-333333333333"
	if got, err = resolver.ResolveSourceSnapshots(ctx, selected); err == nil || len(got) != 0 {
		t.Fatal("replacement process substituted", len(got), err)
	}
	selected[1] = second
	clock.set(permit.LeafUntil)
	if got, err = resolver.ResolveSourceSnapshots(ctx, selected); err == nil || len(got) != 0 {
		t.Fatal("expired stopped grace renewed", len(got), err)
	}
}
