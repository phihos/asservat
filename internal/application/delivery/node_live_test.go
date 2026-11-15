package delivery

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
)

func TestLiveNodeChannelExactFiniteReplyCancellationAndOldNodeClosed(t *testing.T) {
	now := time.Now()
	clk := &clock{t: now}
	ch, e := NewNodeChannel(clk.now, nil)
	if e != nil {
		t.Fatal(e)
	}
	id, e := sourceConnect(ch, epochA)
	if e != nil {
		t.Fatal(e)
	}
	peer := NodePeer{NodeUID: id.NodeUID, PodUID: id.PodUID}
	state := report(now)
	state.Mechanisms = []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable}}
	if e = ch.Report(peer, state); e != nil {
		t.Fatal(e)
	}
	uuid := "33333333-3333-4333-8333-333333333333"
	binding := collector.SourceBinding{RootID: uuid, PolicyUID: "policy", AcceptanceID: uuid, SourceID: uuid, Fence: uuid, ActionID: "packets", PodUID: uuid, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}}
	request := collector.LiveRead{Binding: binding, ClusterID: uuid, NamespaceUID: "ns", WorkloadUID: "workload", Projection: v.Packet, PrivacyUntil: now.Add(time.Hour), Limit: 100, Head: true}
	call, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, e = ch.ReadLive(call, request); e != ErrNodeUnavailable {
		t.Fatal("old collector acquired live capability", e)
	}
	ch.mu.Lock()
	ch.nodes[id.NodeUID].report.Mechanisms[0].LiveProjections = []string{v.Packet}
	ch.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		out, e := ch.ReadLive(call, request)
		if e == nil && (out.SourceID != uuid || out.Position.Sequence != 7) {
			t.Error("substituted reply", out)
		}
		done <- e
	}()
	work, e := ch.Poll(call, peer, epochA, 0, time.Second)
	if e != nil || len(work) != 1 || work[0].Kind != collector.WorkLiveRead || work[0].Live == nil {
		t.Fatal(work, e)
	}
	reply := v.NodeReply{WorkID: work[0].ID, SourceID: uuid, Fence: uuid, BootID: boot, Clock: "monotonic", Sample: 100, Rows: []v.StampedRow{}, Position: v.Position{Sequence: 7}}
	foreign := reply
	foreign.Fence = epochB
	if e = ch.DeliverLive(call, peer, foreign); e == nil {
		t.Fatal("foreign fence reply")
	}
	if e = ch.DeliverLive(call, peer, reply); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = ch.DeliverLive(call, peer, reply); e == nil {
		t.Fatal("reply replayed after handoff")
	}
	canceled, stop := context.WithTimeout(t.Context(), time.Second)
	go func() { _, e := ch.ReadLive(canceled, request); done <- e }()
	if queued, e := ch.Poll(canceled, peer, epochA, work[0].Sequence, time.Second); e != nil || len(queued) != 1 {
		t.Fatal(queued, e)
	}
	stop()
	if e = <-done; e != context.Canceled {
		t.Fatal("original cancellation lost", e)
	}
	ch.mu.Lock()
	pending := len(ch.nodes[id.NodeUID].live)
	remaining := len(ch.nodes[id.NodeUID].work)
	ch.mu.Unlock()
	if pending != 0 || remaining != 0 {
		t.Fatal("canceled viewer retained source task", pending, remaining)
	}
}
