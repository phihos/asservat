package node

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
)

func sampleReport() collector.Report {
	f := collector.Facts{KernelRelease: "6.11.0-1018-azure", Kernel: collector.KernelVersion{Major: 6, Minor: 11}, BTF: collector.Supported, CgroupV2: collector.Supported, BPF: collector.Supported,
		TCX: collector.Supported, TC: collector.Supported, DebugFS: collector.Supported, TraceFS: collector.Supported, BPFFS: collector.Supported, HostProcesses: collector.Supported,
		Runtime: collector.RuntimeContainerd, Engine: collector.Engine{Linked: true, Initialized: true, Version: "v0.57.0"}}
	return collector.Report{Sequence: 4, ObservedAt: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC), Facts: f, Mechanisms: collector.Assess(f),
		Budget:   collector.Usage{Ceilings: collector.Ceilings{RingBytes: 256 << 20, FrozenBytes: 256 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, UploadAvailable: 64 << 20},
		Receipts: []collector.Receipt{{WorkID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Sequence: 2, Outcome: collector.OutcomeRefused, Reason: collector.ReasonRecorderNotImplemented}}}
}

func TestStatusRoundTripsThroughTheClosedWire(t *testing.T) {
	r := sampleReport()
	b, err := json.Marshal(WireStatus("epoch", r))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := contracts.DecodeNodeStatus(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	back, ok := DomainStatus(decoded)
	if !ok || !reflect.DeepEqual(back, r) {
		t.Fatalf("round trip\n got %+v\nwant %+v", back, r)
	}
	// An unparsable kernel is reported as an empty version, not as 0.0.0.
	r.Facts.Kernel = collector.KernelVersion{}
	if w := WireStatus("epoch", r); w.Probe.Kernel != "" {
		t.Fatalf("kernel %q", w.Probe.Kernel)
	} else if _, ok := DomainStatus(w); !ok {
		t.Fatal("empty kernel refused")
	}
}

func TestDomainStatusRefusesOpenValues(t *testing.T) {
	for name, edit := range map[string]func(*contracts.NodeStatus){
		"format":          func(s *contracts.NodeStatus) { s.Format = "other" },
		"sequence":        func(s *contracts.NodeStatus) { s.Sequence = 0 },
		"support value":   func(s *contracts.NodeStatus) { s.Probe.TCX = "maybe" },
		"runtime":         func(s *contracts.NodeStatus) { s.Probe.Runtime = "docker" },
		"kernel mismatch": func(s *contracts.NodeStatus) { s.Probe.Kernel = "6.11" },
		"control text":    func(s *contracts.NodeStatus) { s.Probe.KernelRelease = "6.11\n" },
		"mechanism":       func(s *contracts.NodeStatus) { s.Mechanisms[0].Mechanism = "exec" },
		"adapter":         func(s *contracts.NodeStatus) { s.Mechanisms[0].Adapter = "Maybe" },
		"reason":          func(s *contracts.NodeStatus) { s.Mechanisms[0].Reasons = []string{"Because"} },
		"hook":            func(s *contracts.NodeStatus) { s.Mechanisms[0].Hook = "xdp" },
		"receipt":         func(s *contracts.NodeStatus) { s.Receipts[0].Outcome = "done" },
		"ring over":       func(s *contracts.NodeStatus) { s.Budget.RingReserved = s.Budget.Ceilings.RingBytes + 1 },
		"negative":        func(s *contracts.NodeStatus) { s.Budget.FrozenReserved = -1 },
		"bad ceilings":    func(s *contracts.NodeStatus) { s.Budget.Ceilings.UploadBurstBytes = 0 },
	} {
		s := WireStatus("epoch", sampleReport())
		edit(&s)
		if _, ok := DomainStatus(s); ok {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, ok := DomainWork(contracts.NodeWork{ID: "w", Sequence: 1, Kind: "snapshot", NotAfter: time.Now()}); !ok {
		t.Fatal("work refused")
	}
	if w, ok := DomainWork(contracts.NodeWork{ID: "w", Sequence: 1, Kind: "future", NotAfter: time.Now()}); !ok || w.Kind.Valid() {
		t.Fatal("an unknown kind must reach the node, which answers WorkUnknown")
	}
	for _, w := range []contracts.NodeWork{{Sequence: 1, Kind: "snapshot", NotAfter: time.Now()}, {ID: "w", Kind: "snapshot", NotAfter: time.Now()}, {ID: "w", Sequence: 1, Kind: "snapshot"}} {
		if _, ok := DomainWork(w); ok {
			t.Fatalf("%+v accepted", w)
		}
	}
}
