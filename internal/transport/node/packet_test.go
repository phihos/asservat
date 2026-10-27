package node

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
)

// ADR-248: a packet capture item and its result survive the closed wire; a
// changed digest or an unusable payload stays an invalid item.
func TestPacketCaptureRoundTripsThroughTheClosedWire(t *testing.T) {
	p := collector.PacketCapture{CaptureID: "22222222-2222-4222-8222-222222222222", PodUID: "11111111-1111-4111-8111-111111111111",
		Program: []planning.BPFInstruction{{Code: 6, K: 65535}}, ProgramDigest: [32]byte{1}, Duration: 10 * time.Second, MaxBytes: 8 << 20}
	w := collector.Work{ID: "33333333-3333-4333-8333-333333333333", Sequence: 9, Kind: collector.WorkPacketCapture, NotAfter: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC), Packet: &p}
	b, _ := json.Marshal(contracts.NodePollResponse{Format: contracts.NodePollFormat, Work: []contracts.NodeWork{WireWork(w)}})
	resp, err := contracts.DecodeNodePollResponse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := DomainWork(resp.Work[0])
	if !ok || !reflect.DeepEqual(got, w) || collector.Decide(got, w.NotAfter.Add(-time.Second)).Reason != collector.ReasonRecorderNotImplemented {
		t.Fatalf("%+v %+v", got, got.Packet)
	}
	bad := WireWork(w)
	bad.PacketCapture.ProgramDigest = "zz"
	if got, ok := DomainWork(bad); !ok || got.Packet.Valid() || collector.Decide(got, w.NotAfter.Add(-time.Second)).Reason != collector.ReasonWorkUnknown {
		t.Fatal("an unusable payload must reach the node as an invalid item")
	}
	r := collector.PacketResult{WorkID: w.ID, CaptureID: p.CaptureID, StartedAt: w.NotAfter, EndedAt: w.NotAfter.Add(10 * time.Second), Seen: 5, Retained: 3, Filtered: 2,
		CapturedBytes: 512, Snaplen: 134, EngineVersion: "v0.57.0", ProgramDigest: p.ProgramDigest}
	back, ok := DomainPacketResult(WirePacketResult("epoch", r))
	if !ok || !reflect.DeepEqual(back, r) {
		t.Fatalf("%+v", back)
	}
	r.Seen = 6 // counters must account for every frame
	if _, ok := DomainPacketResult(WirePacketResult("epoch", r)); ok {
		t.Fatal("inconsistent counters accepted")
	}
}
