package delivery

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
)

func TestSourceQueuePreservesCurrentProcessOriginalBoundsAndRestrictiveStop(t *testing.T) {
	for _, mode := range []string{"exact", "foreign-node", "foreign-epoch", "expired", "earlier-request", "stop-without-workload"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			clock := &clock{t: now}
			ch, err := NewNodeChannel(clock.now, nil)
			if err != nil {
				t.Fatal(err)
			}
			id, err := sourceConnect(ch, epochA)
			if err != nil {
				t.Fatal(err)
			}
			peer := NodePeer{NodeUID: id.NodeUID, PodUID: id.PodUID}
			r := report(now)
			r.Mechanisms = []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable}}
			if err = ch.Report(peer, cur(ch, peer), r); err != nil {
				t.Fatal(err)
			}
			resource := collector.SourceResources{PolicyUID: "capacity"}
			uuid := "33333333-3333-4333-8333-333333333333"
			b := collector.SourceBinding{RootID: uuid, PolicyUID: "policy", AcceptanceID: uuid, SourceID: uuid, Fence: uuid, ActionID: "packets", PodUID: uuid, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: SourceResourcesDigest(resource)}
			p := collector.SourcePermit{Binding: b, StartedAt: now, HardUntil: now.Add(24 * time.Hour), StartBy: now.Add(5 * time.Second), IssuedAt: now, DispatchUntil: now.Add(5 * time.Second), LeafUntil: now.Add(30 * time.Second), Credit: 1000, BytesPerSecond: 1000}
			source := collector.PacketSource{Permit: p, Resources: resource, Ring: collector.SourceRingLimits{MaxAge: time.Minute, MaxBytes: 1024, Segments: 4}}
			expected := targets.PacketSourceObservation{PodUID: b.PodUID, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch, ObservedAt: now, FreshUntil: p.DispatchUntil}
			end := p.DispatchUntil
			switch mode {
			case "foreign-node":
				expected.NodeUID = uuid
			case "foreign-epoch":
				expected.CollectorEpoch = uuid
			case "expired":
				source.Permit.DispatchUntil = now
			case "earlier-request":
				end = now.Add(time.Second)
			case "stop-without-workload":
				clock.add(collector.StatusStaleAfter + time.Second)
				end = clock.now().Add(5 * time.Second)
			}
			ctx, cancel := context.WithDeadline(t.Context(), end)
			defer cancel()
			if mode == "stop-without-workload" {
				work, err := ch.EnqueueSourceStop(ctx, b, end)
				if err != nil || work.Kind != collector.WorkStopPacketSource {
					t.Fatal("deleted/stale workload prevented restrictive stop", err)
				}
				return
			}
			work, err := ch.EnqueueSourceExpected(ctx, expected, source)
			if mode != "exact" && mode != "earlier-request" {
				if err == nil {
					t.Fatal("invalid source was queued")
				}
				if v, _ := ch.NodeByName("node"); v.Queued != 0 {
					t.Fatal("refusal left queue effect")
				}
				return
			}
			if err != nil || work.Kind != collector.WorkPacketSource || !work.NotAfter.Equal(end) || work.Source.Permit != p {
				t.Fatal("original source or request bound changed", work, err)
			}
		})
	}
}
