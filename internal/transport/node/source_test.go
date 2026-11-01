package node

import (
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
)

func sourceWireFixture(now time.Time) collector.PacketSource {
	id := "11111111-1111-4111-8111-111111111111"
	resource := collector.SourceResources{PolicyUID: "budget", Node: collector.PolicyLimits{SourceLimits: collector.SourceLimits{MaxActiveSources: 4}, RingBytes: 1 << 20}}
	p := collector.SourcePermit{Binding: collector.SourceBinding{RootID: id, PolicyUID: "policy", AcceptanceID: id, SourceID: id, Fence: id, ActionID: "packets", PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: deliveryapp.SourceResourcesDigest(resource)}, StartedAt: now, HardUntil: now.Add(24 * time.Hour), StartBy: now.Add(5 * time.Second), IssuedAt: now, DispatchUntil: now.Add(5 * time.Second), LeafUntil: now.Add(30 * time.Second), Credit: 1 << 40, BytesPerSecond: 1 << 20}
	return collector.PacketSource{Permit: p, Program: []planning.BPFInstruction{}, Resources: resource, Ring: collector.SourceRingLimits{MaxAge: time.Minute, MaxBytes: 1 << 20, SegmentBytes: 256 << 10, MaxSegments: 4, MaxFrozenBytes: 1 << 20, MaxConcurrentSnapshots: 2}}
}
func TestSourceWorkClosedWireRetainsExactBoundsAndPurpose(t *testing.T) {
	now := time.Now().UTC()
	source := sourceWireFixture(now)
	w := collector.Work{ID: source.Permit.Binding.SourceID, Sequence: 1, Kind: collector.WorkPacketSource, NotAfter: source.Permit.DispatchUntil.Add(-time.Nanosecond), Source: &source}
	back, ok := DomainWork(WireWork(w))
	if !ok || !reflect.DeepEqual(back, w) {
		t.Fatal("source wire changed scope/time", ok, back)
	}
	if r := collector.Decide(back, now); r.Reason == collector.ReasonWorkUnknown {
		t.Fatal("typed source rejected", r)
	}
	for name, change := range map[string]func(*contracts.NodeWork){
		"finite-kind":       func(w *contracts.NodeWork) { w.Kind = string(collector.WorkPacketCapture) },
		"resource-lowering": func(w *contracts.NodeWork) { w.PacketSource.NodeLimits.MaxActiveSources++ },
		"long-leaf": func(w *contracts.NodeWork) {
			w.PacketSource.Permit.LeafUntil = w.PacketSource.Permit.LeafUntil.Add(time.Nanosecond)
		},
		"dispatch-after-original": func(w *contracts.NodeWork) { w.NotAfter = w.PacketSource.Permit.DispatchUntil.Add(time.Nanosecond) },
		"empty-credit":            func(w *contracts.NodeWork) { w.PacketSource.Permit.Credit = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			wire := WireWork(w)
			change(&wire)
			back, ok := DomainWork(wire)
			if ok && collector.Decide(back, now).Reason != collector.ReasonWorkUnknown {
				t.Fatal("invalid source accepted")
			}
		})
	}
	// A previous closed decoder must refuse the new purpose-specific payload.
	raw, _ := json.Marshal(WireWork(w))
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var old struct {
		ID            string                       `json:"id"`
		Sequence      uint64                       `json:"sequence"`
		Kind          string                       `json:"kind"`
		NotAfter      time.Time                    `json:"notAfter"`
		PacketCapture *contracts.NodePacketCapture `json:"packetCapture,omitempty"`
	}
	if dec.Decode(&old) == nil {
		t.Fatal("old node silently consumed new source")
	}
}

func TestSourceStatusMaximumAndUnknownCounterValidation(t *testing.T) {
	r := sampleReport()
	r.ObservedAt = time.Now().UTC()
	r.Facts.KernelRelease = strings.Repeat("\"", 128)
	r.Facts.Engine.Version = strings.Repeat("\"", 64)
	r.Receipts = nil
	for i := 0; i < collector.MaxReceipts; i++ {
		r.Receipts = append(r.Receipts, collector.Receipt{WorkID: strings.Repeat("\"", 36), Sequence: ^uint64(0), Outcome: collector.OutcomeRefused, Reason: collector.ReasonRecorderNotImplemented})
	}
	for i := 0; i < int(collector.SourceStatusLimit); i++ {
		id := fmt.Sprintf("11111111-1111-4111-8111-%012x", i)
		r.Sources = append(r.Sources, collector.SourceStatus{SourceStoppedAt: r.ObservedAt, SnapshotUntil: r.ObservedAt.Add(30 * time.Second), Stopped: true, SourceID: id, Fence: id, IssuedAt: r.ObservedAt, LeafUntil: r.ObservedAt.Add(30 * time.Second), Credit: 1<<63 - 1, ObservedBytes: 1<<63 - 2})
		if i == 15 || i == 1023 || i == int(collector.SourceStatusLimit)-1 {
			raw, err := json.Marshal(WireStatus("epoch", r))
			if err != nil || len(raw) > contracts.NodeStatusMaxRequest {
				t.Fatal("maximum source status overflow", len(raw), err)
			}
			t.Logf("%d source statuses: %d bytes", i+1, len(raw))
		}
	}
	normal := sampleReport()
	normal.ObservedAt = r.ObservedAt
	normal.Sources = r.Sources[:16]
	normalRaw, _ := json.Marshal(WireStatus("epoch", normal))
	t.Logf("16 source statuses with normal base report and maximum counters: %d bytes", len(normalRaw))
	raw, _ := json.Marshal(WireStatus("epoch", r))
	wire, err := contracts.DecodeNodeStatus(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	back, ok := DomainStatus(wire)
	if !ok || len(back.Sources) != int(collector.SourceStatusLimit) {
		t.Fatal("bounded maximum report refused")
	}
	for name, change := range map[string]func(*contracts.NodeStatus){
		"negative":             func(w *contracts.NodeStatus) { w.Sources[0].ObservedBytes = -1 },
		"invented-zero-credit": func(w *contracts.NodeStatus) { w.Sources[0].Credit = 0 },
		"above-credit": func(w *contracts.NodeStatus) {
			w.Sources[0].Credit--
			w.Sources[0].ObservedBytes = w.Sources[0].Credit + 1
		},
		"duplicate-source": func(w *contracts.NodeStatus) { w.Sources[1].SourceID = w.Sources[0].SourceID },
		"over-count":       func(w *contracts.NodeStatus) { w.Sources = append(w.Sources, w.Sources[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			w := WireStatus("epoch", r)
			change(&w)
			if _, ok := DomainStatus(w); ok {
				t.Fatal("invalid counters accepted")
			}
		})
	}
}
