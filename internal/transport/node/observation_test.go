package node

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
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
	data, err := json.Marshal(pollResponse{Work: []contracts.NodeWork{wire}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePollResponse(bytes.NewReader(data))
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
func TestRawPrefixClosedWireRoundTrips(t *testing.T) {
	w := observedNodeWork()
	w.Packet.Raw = &collector.RawPrefix{Snaplen: 96, TCP: 1500}
	data, err := json.Marshal(pollResponse{Work: []contracts.NodeWork{WireWork(w)}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePollResponse(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := DomainWork(decoded.Work[0]); !ok || !reflect.DeepEqual(got, w) || !got.Packet.Valid() {
		t.Fatal("raw prefix changed through closed codec")
	}
	for name, change := range map[string]func(*collector.PacketCapture){
		"unobserved":  func(p *collector.PacketCapture) { p.Observation = nil },
		"over engine": func(p *collector.PacketCapture) { p.Raw.TCP = 1501 },
		"no snaplen":  func(p *collector.PacketCapture) { p.Raw.Snaplen = 0 },
		"no program":  func(p *collector.PacketCapture) { p.Program, p.ProgramDigest = nil, [32]byte{} },
	} {
		bad := observedNodeWork()
		bad.Packet.Raw = &collector.RawPrefix{Snaplen: 96}
		change(bad.Packet)
		if bad.Packet.Valid() {
			t.Fatal(name, "raw capture valid")
		}
	}
}

// ADR-282: an HTTP header projection's bounds cross the closed wire exactly
// and are executable only on an observed capture at the fixed engine snaplen.
func TestHTTPProjectionClosedWireRoundTrips(t *testing.T) {
	http := func() *collector.HTTPProjection {
		return &collector.HTTPProjection{MaxFlows: 1024, MaxHeaderBytes: 32 << 10, MaxFlowBytes: 256 << 10, MaxTotalBytes: 16 << 20, IdleTimeout: 30 * time.Second}
	}
	w := observedNodeWork()
	w.Packet.Raw, w.Packet.HTTP = &collector.RawPrefix{Snaplen: 1500}, http()
	data, err := json.Marshal(pollResponse{Work: []contracts.NodeWork{WireWork(w)}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"http":{"maxFlows":1024,"maxHeaderBytes":32768,"maxFlowBytes":262144,"maxTotalBytes":16777216,"idleTimeoutMillis":30000}`)) {
		t.Fatal("HTTP wire field", string(data))
	}
	decoded, err := decodePollResponse(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := DomainWork(decoded.Work[0]); !ok || !reflect.DeepEqual(got, w) || !got.Packet.Valid() {
		t.Fatal("HTTP projection changed through closed codec")
	}
	for name, change := range map[string]func(*collector.PacketCapture){
		"unobserved":     func(p *collector.PacketCapture) { p.Observation = nil },
		"no raw read":    func(p *collector.PacketCapture) { p.Raw = nil },
		"short snaplen":  func(p *collector.PacketCapture) { p.Raw.Snaplen = 96 },
		"prefix cap":     func(p *collector.PacketCapture) { p.Raw.TCP = 200 },
		"too many flows": func(p *collector.PacketCapture) { p.HTTP.MaxFlows = 1025 },
		"total too big":  func(p *collector.PacketCapture) { p.HTTP.MaxTotalBytes = 16<<20 + 1 },
		"idle too long":  func(p *collector.PacketCapture) { p.HTTP.IdleTimeout = 31 * time.Second },
		"no program":     func(p *collector.PacketCapture) { p.Program, p.ProgramDigest = nil, [32]byte{} },
	} {
		bad := observedNodeWork()
		bad.Packet.Raw, bad.Packet.HTTP = &collector.RawPrefix{Snaplen: 1500}, http()
		change(bad.Packet)
		if bad.Packet.Valid() {
			t.Fatal(name, "HTTP capture valid")
		}
	}
	// A negative idle timeout from the wire is an invalid item, not a panic.
	wire := WireWork(w)
	wire.PacketCapture.HTTP.IdleTimeoutMillis = -1
	if got, ok := DomainWork(wire); !ok || got.Packet.Valid() {
		t.Fatal("negative idle timeout accepted")
	}
}
