package node

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func observedNodeWork() collector.Work {
	now := time.Date(2026, 10, 28, 1, 0, 0, 123000777, time.UTC)
	p := collector.PacketCapture{CaptureID: "22222222-2222-4222-8222-222222222222", PodUID: "11111111-1111-4111-8111-111111111111", Program: []planning.BPFInstruction{{Code: 6, K: 65535}}, ProgramDigest: [32]byte{2}, Duration: time.Second, MaxBytes: 1 << 20}
	p.Observation = &collector.ObservationPermit{Binding: collector.ObservationBinding{Scope: [32]byte{1}, ProgramDigest: p.ProgramDigest, ExpectationDigest: [32]byte{3}, AccountingRule: collector.ObservationAccountingRule(), SessionID: "11111111-1111-4111-8111-111111111111", Fence: "33333333-3333-4333-8333-333333333333", CaptureID: p.CaptureID, ActionID: "action", PodUID: p.PodUID, NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch"}, StartedAt: now, SessionUntil: now.Add(10 * time.Second), LeaseUntil: now.Add(10 * time.Second), StartBy: now.Add(5 * time.Second), Duration: p.Duration, Sequence: 1, Credit: 1 << 20, BytesPerSecond: 1 << 20}
	return collector.Work{ID: "44444444-4444-4444-8444-444444444444", Sequence: 1, Kind: collector.WorkPacketCapture, NotAfter: p.Observation.StartBy, Packet: &p}
}
func TestNodeObservationClosedWireRetainsOriginalPermit(t *testing.T) {
	w := observedNodeWork()
	wire := WireWork(w)
	data, err := json.Marshal(contracts.NodePollResponse{Format: contracts.NodePollFormat, Work: []contracts.NodeWork{wire}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := contracts.DecodeNodePollResponse(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := DomainWork(decoded.Work[0])
	if !ok || !reflect.DeepEqual(got, w) || !got.Packet.Valid() {
		t.Fatal("permit changed through closed codec")
	}
	t.Logf("actual single observed poll JSON bytes=%d", len(data))
	for _, change := range []func(*contracts.NodeObservationPermit){func(p *contracts.NodeObservationPermit) { p.Binding.Scope = "" }, func(p *contracts.NodeObservationPermit) {
		p.Binding.ProgramDigest = strings.ToUpper(p.Binding.AccountingRule)
	}, func(p *contracts.NodeObservationPermit) { p.Credit = 0 }, func(p *contracts.NodeObservationPermit) { p.Binding.CaptureID = "different" }} {
		bad := WireWork(w)
		change(bad.PacketCapture.Observation)
		got, ok := DomainWork(bad)
		if !ok || got.Packet == nil || got.Packet.Valid() {
			t.Fatal("invalid observation downgraded to an executable legacy payload")
		}
	}
	w.Packet.Observation = nil
	legacy, _ := json.Marshal(WireWork(w))
	if bytes.Contains(legacy, []byte("observation")) {
		t.Fatal("nil metadata wire changed")
	}
}
func TestNodeObservationMaximumPollFitsExistingBound(t *testing.T) {
	w := observedNodeWork()
	p := w.Packet
	o := p.Observation
	p.Program = make([]planning.BPFInstruction, planning.MaxFilterInstructions)
	for i := range p.Program {
		p.Program[i] = planning.BPFInstruction{Code: 65535, Jt: 255, Jf: 255, K: ^uint32(0)}
	}
	b := &o.Binding
	b.ActionID = strings.Repeat("a", 128)
	b.NodeUID = strings.Repeat("n", 128)
	b.BootID = strings.Repeat("b", 128)
	b.CollectorPodUID = strings.Repeat("c", 128)
	b.CollectorEpoch = strings.Repeat("e", 128)
	poll := contracts.NodePollResponse{Format: contracts.NodePollFormat, Work: make([]contracts.NodeWork, collector.MaxWorkPerPoll)}
	for i := range poll.Work {
		poll.Work[i] = WireWork(w)
	}
	data, err := json.Marshal(poll)
	if err != nil || len(data) > contracts.NodeMaxResponse {
		t.Fatal("real JSON exceeds unchanged response bound", len(data), err)
	}
	if _, err := contracts.DecodeNodePollResponse(bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual maximal observed poll JSON bytes=%d, ceiling=%d", len(data), contracts.NodeMaxResponse)
}
