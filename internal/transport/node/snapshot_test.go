package node

import (
	"testing"
	"time"

	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

func TestSourceSnapshotWireRetainsExactWindowAndSeparatePurpose(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "11111111-1111-4111-8111-111111111111"
	b := collector.SourceBinding{AudienceDigest: [32]byte{7}, RootID: id, PolicyUID: "policy", AcceptanceID: id, SourceID: id, Fence: id, ActionID: "packets", PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}}
	request := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(deliveryapp.SourceBindingDigest(b)), SourceID: id, Fence: id, SnapshotID: id, SourceStartedAt: now.Add(-time.Minute), SourceHardUntil: now.Add(time.Hour), T0: now.Add(-20 * time.Second), IssuedAt: now, StartBy: now.Add(time.Second), ProcessingUntil: now.Add(time.Minute), Before: time.Second, MaxBytes: 65536}
	x := collector.SourceSnapshot{AttemptID: id, WriterPodUID: id, WriterEpoch: id, Binding: b, CaptureID: id, ExpectationDigest: [32]byte{5}, Request: request}
	work := collector.Work{ID: id, Sequence: 1, Kind: collector.WorkPacketSourceSnapshot, Snapshot: &x, NotAfter: request.StartBy.Add(-time.Millisecond)}
	round, ok := DomainWork(WireWork(work))
	if !ok || round.Snapshot == nil || *round.Snapshot != x || round.Packet != nil || round.Source != nil || !round.NotAfter.Equal(work.NotAfter) || collector.Decide(round, now).Reason == collector.ReasonWorkUnknown {
		t.Fatal("snapshot changed purpose/window", round, ok)
	}
	wire := WireWork(work)
	wire.SourceSnapshot.Binding.Fence = "22222222-2222-4222-8222-222222222222"
	tampered, ok := DomainWork(wire)
	if !ok || collector.Decide(tampered, now).Reason != collector.ReasonWorkUnknown {
		t.Fatal("forged binding accepted", tampered, ok)
	}
	wire = WireWork(work)
	wire.Kind = string(collector.WorkPacketCapture)
	confused, ok := DomainWork(wire)
	if !ok || collector.Decide(confused, now).Reason != collector.ReasonWorkUnknown {
		t.Fatal("snapshot became finite capture")
	}
}

func TestSourceSnapshotCancellationWireCannotBecomeSourceStopOrArm(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "11111111-1111-4111-8111-111111111111"
	b := collector.SourceBinding{AudienceDigest: [32]byte{7}, RootID: id, PolicyUID: "policy", AcceptanceID: id, SourceID: id, Fence: id, ActionID: "packets", PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}}
	q := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(deliveryapp.SourceBindingDigest(b)), SourceID: id, Fence: id, SnapshotID: "66666666-6666-4666-8666-666666666666", SourceStartedAt: now.Add(-time.Minute), SourceHardUntil: now.Add(-time.Second), T0: now.Add(-30 * time.Second), IssuedAt: now.Add(-30 * time.Second), StartBy: now.Add(-25 * time.Second), ProcessingUntil: now.Add(time.Minute), Before: time.Second, MaxBytes: 65536}
	x := collector.SourceSnapshot{Binding: b, CaptureID: "44444444-4444-4444-8444-444444444444", AttemptID: "55555555-5555-4555-8555-555555555555", WriterPodUID: id, WriterEpoch: id, ExpectationDigest: [32]byte{5}, Request: q}
	work := collector.Work{ID: id, Sequence: 2, Kind: collector.WorkCancelSourceSnapshot, NotAfter: now.Add(time.Second), CancelSnapshot: &x}
	wire := WireWork(work)
	round, ok := DomainWork(wire)
	if !ok || round.CancelSnapshot == nil || !round.CancelSnapshot.Equal(x) || round.Snapshot != nil || round.StopSource != nil || collector.Decide(round, now).Reason == collector.ReasonWorkUnknown {
		t.Fatal("lost restrictive expired-source cancellation", round, ok)
	}
	wire.SourceSnapshot = wire.CancelSourceSnapshot
	mixed, ok := DomainWork(wire)
	if ok && collector.Decide(mixed, now).Reason != collector.ReasonWorkUnknown {
		t.Fatal("mixed start/cancel accepted", mixed)
	}
	wire = WireWork(work)
	wire.Kind = string(collector.WorkStopPacketSource)
	confused, ok := DomainWork(wire)
	if ok && collector.Decide(confused, now).Reason != collector.ReasonWorkUnknown {
		t.Fatal("snapshot cancel became source stop", confused)
	}
}
