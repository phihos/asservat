package delivery

import (
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"testing"
	"time"
)

func TestPacketObservationExpectedSourceAndOriginalFitBeforeQueue(t *testing.T) {
	for _, mode := range []string{"exact", "legacy", "node", "boot", "collector", "epoch", "capture", "program", "duration", "start", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ch, _, clk, _ := newChannel(t)
			peer, _ := enroll(t, ch, epochA)
			r := report(1, clk.now())
			r.Mechanisms = []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable}}
			if err := ch.Report(peer, epochA, r); err != nil {
				t.Fatal(err)
			}
			v, _ := ch.NodeByName("node-a")
			s := targets.PacketSourceObservation{PodUID: "33333333-3333-4333-8333-333333333333", NodeUID: v.Identity.NodeUID, BootID: v.Identity.BootID, CollectorPodUID: v.Identity.PodUID, CollectorEpoch: v.Identity.Epoch, ObservedAt: clk.now(), FreshUntil: clk.now().Add(5 * time.Second)}
			p := collector.PacketCapture{CaptureID: "22222222-2222-4222-8222-222222222222", PodUID: s.PodUID, Program: []planning.BPFInstruction{{Code: 6, K: 65535}}, ProgramDigest: [32]byte{2}, Duration: time.Second, MaxBytes: 1 << 20}
			p.Observation = &collector.ObservationPermit{Binding: collector.ObservationBinding{Scope: [32]byte{1}, ProgramDigest: p.ProgramDigest, ExpectationDigest: [32]byte{3}, AccountingRule: collector.ObservationAccountingRule(), SessionID: "11111111-1111-4111-8111-111111111111", Fence: "44444444-4444-4444-8444-444444444444", CaptureID: p.CaptureID, ActionID: "action", PodUID: s.PodUID, NodeUID: s.NodeUID, BootID: s.BootID, CollectorPodUID: s.CollectorPodUID, CollectorEpoch: s.CollectorEpoch}, StartedAt: clk.now(), SessionUntil: clk.now().Add(10 * time.Second), LeaseUntil: clk.now().Add(10 * time.Second), StartBy: clk.now().Add(5 * time.Second), Duration: p.Duration, Sequence: 1, Credit: 1 << 20, BytesPerSecond: 1 << 20}
			start := p.Observation.StartBy
			switch mode {
			case "node":
				p.Observation.Binding.NodeUID = "other"
			case "boot":
				p.Observation.Binding.BootID = "other"
			case "collector":
				p.Observation.Binding.CollectorPodUID = "other"
			case "epoch":
				p.Observation.Binding.CollectorEpoch = "other"
			case "capture":
				p.Observation.Binding.CaptureID = "other"
			case "program":
				p.Observation.Binding.ProgramDigest[0]++
			case "duration":
				p.Observation.Duration += time.Second
			case "start":
				start = start.Add(time.Nanosecond)
			case "expired":
				clk.add(5 * time.Second)
			}
			var w collector.Work
			var err error
			if mode == "legacy" {
				w, err = ch.EnqueuePacket(s.NodeUID, p, start)
			} else {
				w, err = ch.EnqueuePacketExpected(context.Background(), s, p, start)
			}
			v, _ = ch.NodeByName("node-a")
			if mode != "exact" {
				if err == nil || w.ID != "" || v.Queued != 0 {
					t.Fatal("invalid permit affected queue", mode, err)
				}
				return
			}
			if err != nil || v.Queued != 1 {
				t.Fatal(err, v)
			}
			p.Observation.Credit++
			p.Program[0].K++
			polled, err := ch.Poll(context.Background(), peer, epochA, 0, 0)
			if err != nil || len(polled) != 1 || polled[0].Packet.Observation.Credit != 1<<20 || polled[0].Packet.Program[0].K != 65535 || !polled[0].NotAfter.Equal(start) {
				t.Fatal("caller mutated queued original permit/program", err)
			}
		})
	}
}
