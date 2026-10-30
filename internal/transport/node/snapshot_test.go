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
