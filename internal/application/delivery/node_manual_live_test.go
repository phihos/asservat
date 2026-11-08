package delivery

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
)

func TestLiveManualNodeChannelMatchesOriginalHolderAndInspectionIsPassive(t *testing.T) {
	now := time.Now()
	clk := &clock{t: now}
	ch, e := NewNodeChannel(sourceNodeAttester{}, &fakeIssuer{}, clk.now, nil)
	if e != nil {
		t.Fatal(e)
	}
	_, _, id, e := ch.Enroll(t.Context(), "127.0.0.1", []byte("token"), []byte("csr"), boot, epochA)
	if e != nil {
		t.Fatal(e)
	}
	peer := NodePeer{NodeUID: id.NodeUID, Epoch: id.Epoch}
	state := report(1, now)
	state.Mechanisms = []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable, LiveProjections: []string{v.Packet}}}
	if e = ch.Report(peer, epochA, state); e != nil {
		t.Fatal(e)
	}
	uid := "33333333-3333-4333-8333-333333333333"
	m := collector.ManualLiveSource{RootID: uid, ExecutorPodUID: uid, ExecutorEpoch: uid, CaptureID: uid, AttemptID: uid, ActionID: "packet", WorkID: uid, PodUID: uid, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}}
	r := collector.LiveRead{Manual: &m, Inspect: true, Head: true, ClusterID: uid, NamespaceUID: "ns", WorkloadUID: "work", Projection: v.Packet, PrivacyUntil: now.Add(time.Minute), Limit: 20}
	call, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := ch.ReadLive(call, r); done <- e }()
	work, e := ch.Poll(call, peer, epochA, 0, time.Second)
	if e != nil || len(work) != 1 || work[0].Packet != nil || work[0].Source != nil || work[0].Live == nil || !work[0].Live.Inspect {
		t.Fatal("passive manual purpose", work, e)
	}
	m.StartedAt = now
	m.HardUntil = now.Add(time.Minute)
	reply := v.NodeReply{Manual: &m, WorkID: work[0].ID, SourceID: m.CaptureID, Fence: m.WorkID, BootID: m.BootID, Clock: "monotonic", Sample: 100, Rows: []v.StampedRow{}}
	for _, mode := range []string{"missing", "work", "capture", "permit", "head-row"} {
		bad := reply
		n := m
		bad.Manual = &n
		switch mode {
		case "missing":
			bad.Manual = nil
		case "work":
			n.WorkID = epochB
		case "capture":
			n.CaptureID = epochB
		case "permit":
			n.ObservationKind = "packet"
			n.ObservationSessionID = epochB
			n.ObservationFence = epochB
		case "head-row":
			bad.Rows = []v.StampedRow{{}}
		}
		if e = ch.DeliverLive(call, peer, epochA, bad); e == nil {
			t.Fatal("substituted or disclosing inspection", mode)
		}
	}
	if e = ch.DeliverLive(call, peer, epochA, reply); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	r.Manual = &m
	r.Inspect = false
	r.Head = false
	go func() { _, e := ch.ReadLive(call, r); done <- e }()
	next, e := ch.Poll(call, peer, epochA, work[0].Sequence, time.Second)
	if e != nil || len(next) != 1 {
		t.Fatal(next, e)
	}
	reply.WorkID = next[0].ID
	original := m
	m.HardUntil = m.HardUntil.Add(time.Millisecond)
	reply.Manual = &original
	replacement := reply
	n := m
	replacement.Manual = &n
	if e = ch.DeliverLive(call, peer, epochA, replacement); e == nil {
		t.Fatal("replacement/renewed source time accepted")
	}
	if e = ch.DeliverLive(call, peer, epochA, reply); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = ch.DeliverLive(call, peer, epochA, reply); e == nil {
		t.Fatal("manual reply replayed after handoff")
	}
}
