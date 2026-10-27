package bootstrap

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/application/delivery"
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
			nodes := &packetTargetNodes{view: delivery.NodeView{Current: true, ReportedAt: now.Add(-collector.StatusStaleAfter + time.Second), Report: &collector.Report{Mechanisms: []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable}}}}}
			h := &ConnectorRecordings{nodes: nodes}
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
			p := targets.PodResolution{ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
			got := r.packetTargetAvailability(p, node)
			want := targets.RecorderUnavailable
			if mode == "available" {
				want = targets.RecorderAvailable
			}
			if mode == "no-node" {
				want = targets.RecorderNoNode
			}
			if got.Target != p || got.Recorder.Outcome != want {
				t.Fatal("inherited availability from another or stale node", got)
			}
			if node != "" && r.recordings != nil && (len(nodes.names) != 1 || nodes.names[0] != node) {
				t.Fatal("used another node or repeated discovery", nodes.names)
			}
		})
	}
}
