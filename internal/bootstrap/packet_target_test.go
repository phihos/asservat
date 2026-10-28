package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
)

type packetTargetNodes struct {
	fakeRecordingNodes
	view  delivery.NodeView
	names []string
}

func (n *packetTargetNodes) NodeByName(name string) (delivery.NodeView, bool) {
	n.names = append(n.names, name)
	return n.view, name == "worker"
}
func TestPacketTargetAvailabilityUsesOnlyObservedNodeWithoutChangingTargetBound(t *testing.T) {
	now := time.Now().UTC()
	for _, mode := range []string{"available", "different-node", "no-node", "missing-collector", "stale-report", "adapter-unavailable", "no-report", "no-holder"} {
		t.Run(mode, func(t *testing.T) {
			// A report nearing its status boundary remains a point-in-time
			// availability answer; it must not shorten the target proof.
			nodes := &packetTargetNodes{view: delivery.NodeView{Identity: collector.Identity{NodeUID: "node", BootID: "boot", PodUID: "collector", Epoch: "epoch"}, Current: true, ReportedAt: now.Add(-collector.StatusStaleAfter + time.Second), Report: &collector.Report{Mechanisms: []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable}}}}}
			h := &ConnectorRecordings{nodes: nodes, now: func() time.Time { return now }}
			r := reportedTargets{recordings: h}
			node := "worker"
			switch mode {
			case "different-node":
				node = "replacement-node"
			case "no-node":
				node = ""
			case "missing-collector", "stale-report":
				nodes.view.Current = false
			case "adapter-unavailable":
				nodes.view.Report.Mechanisms[0].Adapter = collector.AdapterUnavailable
			case "no-report":
				nodes.view.Report = nil
			case "no-holder":
				r.recordings = nil
			}
			p := targets.PodResolution{Pin: artifact.PinnedPod{UID: "target"}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
			got := r.packetTargetAvailability(context.Background(), p, node, false)
			want := targets.RecorderUnavailable
			if mode == "available" {
				want = targets.RecorderAvailable
			}
			if mode == "no-node" {
				want = targets.RecorderNoNode
			}
			if got.Target != p || got.Recorder.Outcome != want || got.Recorder.Source != nil {
				t.Fatal("inherited availability from another or stale node", got)
			}
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var legacy struct {
				Target   targets.PodResolution
				Recorder struct{ Outcome string }
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&legacy); err != nil {
				t.Fatal("ordinary metadata wire changed", err, string(raw))
			}
			if node != "" && r.recordings != nil && (len(nodes.names) != 1 || nodes.names[0] != node) {
				t.Fatal("used another node or repeated discovery", nodes.names)
			}
		})
	}
}

func TestPacketSourceObservationRetainsOriginalIntervals(t *testing.T) {
	now := time.Now().UTC()
	for _, mode := range []string{"exact", "node-cutoff", "caller-cutoff", "later-node-start", "disjoint", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			p := targets.PodResolution{Pin: artifact.PinnedPod{UID: "target"}, ObservedAt: now.Add(-2 * time.Second), FreshUntil: now.Add(3 * time.Second)}
			nodes := &packetTargetNodes{view: delivery.NodeView{Identity: collector.Identity{NodeUID: "node-uid", BootID: "boot", PodUID: "collector", Epoch: "epoch"}, Current: true, ReportedAt: now.Add(-10 * time.Second), Report: &collector.Report{Mechanisms: []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable}}}}}
			ctx := context.Background()
			wantStart, wantUntil := p.ObservedAt, p.FreshUntil
			switch mode {
			case "node-cutoff":
				nodes.view.ReportedAt = now.Add(-collector.StatusStaleAfter + time.Second)
				wantUntil = now.Add(time.Second)
			case "caller-cutoff":
				var cancel context.CancelFunc
				wantUntil = now.Add(time.Second)
				ctx, cancel = context.WithDeadline(ctx, wantUntil)
				defer cancel()
			case "later-node-start":
				nodes.view.ReportedAt = now.Add(-time.Second)
				wantStart = nodes.view.ReportedAt
			case "disjoint":
				nodes.view.ReportedAt = p.FreshUntil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			resolver := reportedTargets{recordings: &ConnectorRecordings{nodes: nodes, now: func() time.Time { return now }}}
			got := resolver.packetTargetAvailability(ctx, p, "worker", true)
			if got.Target != p || got.Recorder.Outcome != targets.RecorderAvailable || len(nodes.names) != 1 {
				t.Fatal("metadata path or discovery changed", got, nodes.names)
			}
			source := got.Recorder.Source
			if mode == "disjoint" || mode == "cancelled" {
				if source != nil {
					t.Fatal("minted source from invalid original interval", source)
				}
				return
			}
			if source == nil || !source.Valid(now) || source.PodUID != "target" || source.NodeUID != "node-uid" || source.BootID != "boot" || source.CollectorPodUID != "collector" || source.CollectorEpoch != "epoch" || !source.ObservedAt.Equal(wantStart) || !source.FreshUntil.Equal(wantUntil) {
				t.Fatal("source facts changed or interval refreshed", source, wantStart, wantUntil)
			}
		})
	}
}
