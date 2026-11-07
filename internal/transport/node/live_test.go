package node

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestLiveWorkWireNeverBecomesAcquisitionAndRetainsOriginalDeadline(t *testing.T) {
	now := time.Now()
	p := sourceWireFixture(now).Permit
	r := collector.LiveRead{Binding: p.Binding, ClusterID: p.Binding.RootID, NamespaceUID: "ns", WorkloadUID: "work", Projection: v.Packet, PrivacyUntil: p.HardUntil, Limit: 100}
	w := collector.Work{ID: p.Binding.SourceID, Sequence: 1, Kind: collector.WorkLiveRead, NotAfter: now.Add(time.Second), Live: &r}
	raw, e := json.Marshal(contracts.NodePollResponse{Format: contracts.NodePollFormat, Work: []contracts.NodeWork{WireWork(w)}})
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := contracts.DecodeNodePollResponse(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	back, ok := DomainWork(decoded.Work[0])
	encoded, _ := json.Marshal(back.Live)
	original, _ := json.Marshal(r)
	if !ok || back.Live == nil || !bytes.Equal(encoded, original) || !back.NotAfter.Equal(w.NotAfter) || back.Packet != nil || back.Source != nil || collector.Decide(back, now).Reason == collector.ReasonWorkUnknown {
		t.Fatal("changed live source or purpose", back, e)
	}
	wire := WireWork(w)
	wire.PacketCapture = &contracts.NodePacketCapture{}
	confused, _ := DomainWork(wire)
	if collector.Decide(confused, now).Reason != collector.ReasonWorkUnknown {
		t.Fatal("mixed acquisition accepted")
	}
}
func TestLiveApprovedReplyStrictCodecPreservesZerosAndRejectsPayload(t *testing.T) {
	now := time.Now()
	id := "11111111-1111-4111-8111-111111111111"
	zero := 0
	row := v.Row{ID: id + ":1", SourceID: id, Sequence: 1, PodUID: id, Projection: v.Packet, ObservedAt: now, ReceivedAt: now, ExpiresAt: now.Add(time.Second), Packet: &v.PacketFields{Protocol: "TCP", RemoteIP: "192.0.2.1", Direction: "egress", PID: &zero}}
	// PID zero is unavailable, unlike a genuine zero port.
	row.Packet.PID = nil
	in := v.NodeReply{WorkID: id, SourceID: id, Fence: id, BootID: id, Clock: "monotonic", Sample: 100, Rows: []v.StampedRow{{Row: row, Nanos: 99, Clock: "monotonic"}}, Position: v.Position{Sequence: 1}}
	wire, e := WireLiveReply(id, in)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(wire)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := contracts.DecodeNodeLiveResult(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	out, e := DomainLiveReply(decoded)
	if e != nil || len(out.Rows) != 1 || out.Rows[0].Row.Packet.RemotePort != 0 || out.Rows[0].Row.Packet.PID != nil || out.Rows[0].Nanos != 99 {
		t.Fatal(out, e)
	}
	wire.Rows[0].Row = bytes.ReplaceAll(wire.Rows[0].Row, []byte(`"protocol":"TCP"`), []byte(`"protocol":"TCP","payload":"SECRET"`))
	if _, e = DomainLiveReply(wire); e == nil {
		t.Fatal("raw field accepted")
	}
}

func TestLiveReplyCannotTurnMissingNullableOrZeroFieldsIntoObservedFacts(t *testing.T) {
	now := time.Now()
	id := "11111111-1111-4111-8111-111111111111"
	row := v.Row{ID: id + ":1", SourceID: id, Sequence: 1, PodUID: id, Projection: v.Syscall, ObservedAt: now, ReceivedAt: now, ExpiresAt: now.Add(time.Second), Syscall: &v.SyscallFields{PID: 1, Name: "read", Error: false, Paired: false}}
	wire, e := WireLiveReply(id, v.NodeReply{WorkID: id, SourceID: id, Fence: id, BootID: id, Clock: "boottime", Sample: 100, Rows: []v.StampedRow{{Row: row, Nanos: 99, Clock: "boottime"}}, Position: v.Position{Sequence: 1}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DomainLiveReply(wire); e != nil {
		t.Fatal("known false rejected", e)
	}
	original := append([]byte(nil), wire.Rows[0].Row...)
	for _, mode := range []string{"missing-false", "missing-null", "missing-generation", "duplicate-false"} {
		t.Run(mode, func(t *testing.T) {
			var body map[string]json.RawMessage
			if json.Unmarshal(original, &body) != nil {
				t.Fatal("invalid fixture")
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(body["fields"], &fields)
			switch mode {
			case "missing-false":
				delete(fields, "error")
			case "missing-null":
				delete(fields, "errno")
			case "missing-generation":
				delete(body, "filter_generation")
			}
			body["fields"], _ = json.Marshal(fields)
			wire.Rows[0].Row, _ = json.Marshal(body)
			if mode == "duplicate-false" {
				wire.Rows[0].Row = bytes.Replace(wire.Rows[0].Row, []byte(`"error":false`), []byte(`"error":false,"error":false`), 1)
			}
			if _, e = DomainLiveReply(wire); e == nil {
				t.Fatal("missing/ambiguous field became an observation")
			}
		})
	}
}
