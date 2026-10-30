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

type retainedSourceRegistry struct{ view delivery.NodeView }

func (r *retainedSourceRegistry) NodeByName(string) (delivery.NodeView, bool) {
	panic("snapshot looked up a replacement target")
}
func (r *retainedSourceRegistry) EnqueuePacket(string, collector.PacketCapture, time.Time) (collector.Work, error) {
	panic("snapshot armed a finite recorder")
}
func (r *retainedSourceRegistry) NodeByUID(uid string) (delivery.NodeView, bool) {
	return r.view, uid == r.view.Identity.NodeUID
}

func TestSourceSnapshotResolutionUsesRetainedPinAndActualStopGrace(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Microsecond)
	clock := &packetRingClock{at: start.Add(3 * time.Second)}
	p := sourceOwnerPermit(start)
	id := p.Binding.PodUID
	request := targets.Request{ClusterID: id, Namespace: configuration.NamespaceRef{Name: "app", UID: id}, Workload: configuration.WorkloadRef{Kind: "Pod", Name: "old-pod", UID: id}, PodName: "old-pod", PodUID: id}
	original := targets.SourceSnapshotTarget{Request: request, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "old-pod", UID: id}, NodeUID: p.Binding.NodeUID, BootID: p.Binding.BootID, CollectorPodUID: p.Binding.CollectorPodUID, CollectorEpoch: p.Binding.CollectorEpoch, SourceID: p.Binding.SourceID, Fence: p.Binding.Fence, BindingDigest: [32]byte{1}}
	registry := &retainedSourceRegistry{view: delivery.NodeView{Identity: collector.Identity{NodeUID: p.Binding.NodeUID, BootID: p.Binding.BootID, PodUID: p.Binding.CollectorPodUID, Epoch: p.Binding.CollectorEpoch}, Current: true, Report: &collector.Report{ObservedAt: start.Add(2 * time.Second), Sources: []collector.SourceStatus{{SourceID: p.Binding.SourceID, Fence: p.Binding.Fence, IssuedAt: p.IssuedAt, LeafUntil: p.LeafUntil, Credit: p.Credit, Stopped: true, SourceStoppedAt: start.Add(time.Second), SnapshotUntil: p.LeafUntil}}}}}
	// No PodTargets is provided: this branch cannot read or resurrect a Pod.
	resolver := reportedTargets{recordings: &ConnectorRecordings{nodes: registry, now: clock.now}}
	ctx, cancel := context.WithDeadline(t.Context(), start.Add(time.Minute))
	defer cancel()
	out, err := resolver.ResolveSourceSnapshot(ctx, original)
	if err != nil || out.Original != original || !out.Valid(clock.now()) || !out.State.SourceStoppedAt.Equal(start.Add(time.Second)) || out.ReportedAt != registry.view.Report.ObservedAt {
		t.Fatal("lost retained target/actual report", out, err)
	}
	registry.view.Identity.BootID = "22222222-2222-4222-8222-222222222222"
	if _, err = resolver.ResolveSourceSnapshot(ctx, original); err == nil {
		t.Fatal("reused replacement node boot")
	}
	registry.view.Identity.BootID = original.BootID
	registry.view.Report.Sources[0].Closed = true
	if _, err = resolver.ResolveSourceSnapshot(ctx, original); err == nil {
		t.Fatal("snapshot terminal source")
	}
	registry.view.Report.Sources[0].Closed = false
	clock.set(p.LeafUntil)
	if _, err = resolver.ResolveSourceSnapshot(ctx, original); err == nil {
		t.Fatal("natural grace widened expired source leaf")
	}
}
