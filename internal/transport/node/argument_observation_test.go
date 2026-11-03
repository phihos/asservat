package node

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func argumentNodeWork() collector.Work {
	w := observedNodeWork()
	p := w.Packet
	old := p.Observation
	b := old.Binding
	p.Program = p.Program[:0]
	p.ProgramDigest = [32]byte{}
	p.Observation = nil
	p.Syscalls = &collector.SyscallFilter{Names: []string{"write"}, MaxEvents: 100, MaxTrackedThreads: 16}
	p.MaxEventsPerSecond = 100
	p.Arguments = &collector.ArgumentObservationPermit{Binding: collector.ArgumentObservationBinding{Scope: b.Scope, ProgramDigest: [32]byte{2}, DefinitionDigest: [32]byte{3}, ExpectationDigest: b.ExpectationDigest, AccountingRule: collector.ArgumentObservationAccountingRule(), SessionID: b.SessionID, Fence: b.Fence, CaptureID: b.CaptureID, ActionID: b.ActionID, PodUID: b.PodUID, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch}, StartedAt: old.StartedAt, SessionUntil: old.StartBy.Add(p.Duration), LeaseUntil: old.StartBy.Add(p.Duration), StartBy: old.StartBy, Duration: p.Duration, Sequence: 1, EventCredit: 1000, ByteCredit: 1 << 20, EventsPerSecond: 100, BytesPerSecond: 1 << 20, MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxTrackedThreads: 16, CaptureBuffers: true}
	w.Kind = collector.WorkSyscallCapture
	return w
}
func TestArgumentPermitClosedWireNoPacketFallback(t *testing.T) {
	w := argumentNodeWork()
	if !w.Packet.Valid() {
		t.Fatal("fixture")
	}
	raw, err := json.Marshal(contracts.NodePollResponse{Format: contracts.NodePollFormat, Work: []contracts.NodeWork{WireWork(w)}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := contracts.DecodeNodePollResponse(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := DomainWork(decoded.Work[0])
	if !ok || !reflect.DeepEqual(got, w) || !got.Packet.Valid() {
		t.Fatal(got, w)
	}
	for _, change := range []func(*contracts.NodeArgumentObservationPermit){func(a *contracts.NodeArgumentObservationPermit) { a.Binding.DefinitionDigest = "" }, func(a *contracts.NodeArgumentObservationPermit) { a.EventCredit = 0 }, func(a *contracts.NodeArgumentObservationPermit) { a.StartBy = a.StartBy.Add(time.Second) }, func(a *contracts.NodeArgumentObservationPermit) { a.MaxTrackedThreads++ }} {
		wire := WireWork(w)
		change(wire.PacketCapture.Arguments)
		got, ok := DomainWork(wire)
		if !ok || got.Packet == nil || got.Packet.Valid() {
			t.Fatal("invalid argument permit fell back", got)
		}
	}
	w.Packet.Observation = observedNodeWork().Packet.Observation
	if w.Packet.Valid() {
		t.Fatal("packet observation accepted for arguments")
	}
}
