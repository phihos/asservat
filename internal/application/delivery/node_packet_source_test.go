package delivery

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
)

func TestPacketExpectedSourceChecksBeforeQueueEffect(t *testing.T) {
	for _, mode := range []string{"exact", "foreign-target", "foreign-node", "foreign-boot", "foreign-collector", "foreign-epoch", "expired", "future-observation", "cancelled", "deadline", "late-start", "stale-report", "rotated-before-enqueue", "rotated-after-enqueue"} {
		t.Run(mode, func(t *testing.T) {
			ch, _, clk, _ := newChannel(t)
			peer, _ := enroll(t, ch, epochA)
			r := report(1, clk.now())
			r.Mechanisms = []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable}}
			if err := ch.Report(peer, epochA, r); err != nil {
				t.Fatal(err)
			}
			v, ok := ch.NodeByName("node-a")
			if !ok {
				t.Fatal("missing authenticated view")
			}
			source := targets.PacketSourceObservation{PodUID: "33333333-3333-4333-8333-333333333333", NodeUID: v.Identity.NodeUID, BootID: v.Identity.BootID, CollectorPodUID: v.Identity.PodUID, CollectorEpoch: v.Identity.Epoch, ObservedAt: clk.now(), FreshUntil: clk.now().Add(5 * time.Second)}
			packet := collector.PacketCapture{CaptureID: "22222222-2222-4222-8222-222222222222", PodUID: "33333333-3333-4333-8333-333333333333", Duration: 10 * time.Second, MaxBytes: 1 << 20}
			ctx := context.Background()
			startBy := clk.now().Add(10 * time.Second)
			switch mode {
			case "foreign-target":
				source.PodUID = "other"
			case "foreign-node":
				source.NodeUID = "other"
			case "foreign-boot":
				source.BootID = "other"
			case "foreign-collector":
				source.CollectorPodUID = "other"
			case "foreign-epoch":
				source.CollectorEpoch = epochB
			case "expired":
				source.FreshUntil = clk.now()
			case "future-observation":
				source.ObservedAt = clk.now().Add(time.Second)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			case "late-start":
				startBy = startBy.Add(time.Nanosecond)
			case "stale-report":
				clk.add(collector.StatusStaleAfter + time.Second)
				source.ObservedAt = clk.now()
				source.FreshUntil = clk.now().Add(time.Second)
				startBy = clk.now().Add(time.Second)
			case "rotated-before-enqueue":
				peer, _ = enroll(t, ch, epochB)
			}
			work, err := ch.EnqueuePacketExpected(ctx, source, packet, startBy)
			v, _ = ch.NodeByName("node-a")
			if mode != "exact" && mode != "rotated-after-enqueue" {
				if err == nil || work.ID != "" || v.Queued != 0 {
					t.Fatalf("refusal had queue effect: %+v %+v %v", work, v, err)
				}
				return
			}
			if err != nil || v.Queued != 1 || !work.NotAfter.Equal(startBy) {
				t.Fatal(work, v, err)
			}
			if mode == "rotated-after-enqueue" {
				replacement, _ := enroll(t, ch, epochB)
				polled, err := ch.Poll(context.Background(), replacement, epochB, 0, 0)
				if err != nil || len(polled) != 0 {
					t.Fatal("replacement inherited work before first poll", polled, err)
				}
				return
			}
			// Fresh source facts authorize enqueue, not a new short lifetime for work.
			clk.add(6 * time.Second)
			polled, err := ch.Poll(context.Background(), peer, epochA, 0, 0)
			if err != nil || len(polled) != 1 || polled[0].ID != work.ID {
				t.Fatal("issued work lost original start bound", polled, err)
			}
			// A later epoch cannot inherit even a previously polled queued item.
			replacement, _ := enroll(t, ch, epochB)
			polled, err = ch.Poll(context.Background(), replacement, epochB, 0, 0)
			if err != nil || len(polled) != 0 {
				t.Fatal("replacement inherited work", polled, err)
			}
		})
	}
}
