// Package node is the HTTP transport of the private node work channel
// (ADR-246, I-02): the connector's handler and the collector's client. It
// converts between the closed wire DTOs and the collector domain values; the
// delivery package owns all channel state.
package node

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
)

// WireStatus converts one report into its wire form.
func WireStatus(epoch string, r collector.Report) contracts.NodeStatus {
	f := r.Facts
	kernel := ""
	if f.Kernel != (collector.KernelVersion{}) {
		kernel = f.Kernel.String()
	}
	out := contracts.NodeStatus{Format: contracts.NodeStatusFormat, Epoch: epoch, Sequence: r.Sequence, ObservedAt: r.ObservedAt.UTC(),
		Probe: contracts.NodeProbe{KernelRelease: f.KernelRelease, Kernel: kernel, BTF: string(f.BTF), CgroupV2: string(f.CgroupV2), BPF: string(f.BPF),
			TCX: string(f.TCX), TC: string(f.TC), DebugFS: string(f.DebugFS), TraceFS: string(f.TraceFS), BPFFS: string(f.BPFFS), HostProcesses: string(f.HostProcesses),
			Runtime: string(f.Runtime), Engine: contracts.NodeEngine{Linked: f.Engine.Linked, Initialized: f.Engine.Initialized, Version: f.Engine.Version}},
		Mechanisms: []contracts.NodeAdapter{}, Receipts: []contracts.NodeReceipt{},
		Budget: contracts.NodeBudget{Ceilings: WireCeilings(r.Budget.Ceilings), RingReserved: r.Budget.RingReserved, FrozenReserved: r.Budget.FrozenReserved, UploadAvailable: r.Budget.UploadAvailable}}
	for _, m := range r.Mechanisms {
		a := contracts.NodeAdapter{Mechanism: string(m.Mechanism), Prerequisites: m.Prerequisites, Adapter: string(m.Adapter), Hook: string(m.Hook), Reasons: []string{}}
		for _, reason := range m.Reasons {
			a.Reasons = append(a.Reasons, string(reason))
		}
		out.Mechanisms = append(out.Mechanisms, a)
	}
	for _, rc := range r.Receipts {
		out.Receipts = append(out.Receipts, contracts.NodeReceipt{WorkID: rc.WorkID, Sequence: rc.Sequence, Outcome: string(rc.Outcome), Reason: string(rc.Reason)})
	}
	return out
}

func WireCeilings(c collector.Ceilings) contracts.NodeCeilings {
	return contracts.NodeCeilings{RingBytes: c.RingBytes, FrozenBytes: c.FrozenBytes, UploadBytesPerSecond: c.UploadBytesPerSecond, UploadBurstBytes: c.UploadBurstBytes}
}

func DomainCeilings(c contracts.NodeCeilings) collector.Ceilings {
	return collector.Ceilings{RingBytes: c.RingBytes, FrozenBytes: c.FrozenBytes, UploadBytesPerSecond: c.UploadBytesPerSecond, UploadBurstBytes: c.UploadBurstBytes}
}

func text(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func support(s string) (collector.Support, bool) {
	v := collector.Support(s)
	return v, v.Valid()
}

// DomainStatus validates a wire report and converts it. Every enumerated
// value must be one of the closed values; free text is short printable ASCII.
func DomainStatus(s contracts.NodeStatus) (collector.Report, bool) {
	var r collector.Report
	if s.Format != contracts.NodeStatusFormat || s.Sequence == 0 || s.ObservedAt.IsZero() || len(s.Mechanisms) > 8 || len(s.Receipts) > collector.MaxReceipts {
		return r, false
	}
	p := s.Probe
	kernel, err := collector.ParseKernelRelease(p.Kernel)
	if p.Kernel != "" && (err != nil || kernel.String() != p.Kernel) {
		return r, false
	}
	if !text(p.KernelRelease, 128) || !text(p.Engine.Version, 64) {
		return r, false
	}
	f := collector.Facts{KernelRelease: p.KernelRelease, Kernel: kernel, Runtime: collector.Runtime(p.Runtime), Engine: collector.Engine{Linked: p.Engine.Linked, Initialized: p.Engine.Initialized, Version: p.Engine.Version}}
	ok := true
	for _, x := range []struct {
		in  string
		out *collector.Support
	}{{p.BTF, &f.BTF}, {p.CgroupV2, &f.CgroupV2}, {p.BPF, &f.BPF}, {p.TCX, &f.TCX}, {p.TC, &f.TC}, {p.DebugFS, &f.DebugFS}, {p.TraceFS, &f.TraceFS}, {p.BPFFS, &f.BPFFS}, {p.HostProcesses, &f.HostProcesses}} {
		v, valid := support(x.in)
		*x.out, ok = v, ok && valid
	}
	if !ok || (f.Runtime != collector.RuntimeUnknown && f.Runtime != collector.RuntimeContainerd && f.Runtime != collector.RuntimeCRIO) {
		return r, false
	}
	r = collector.Report{Sequence: s.Sequence, ObservedAt: s.ObservedAt.UTC(), Facts: f, Mechanisms: []collector.Availability{}, Receipts: []collector.Receipt{},
		Budget: collector.Usage{Ceilings: DomainCeilings(s.Budget.Ceilings), RingReserved: s.Budget.RingReserved, FrozenReserved: s.Budget.FrozenReserved, UploadAvailable: s.Budget.UploadAvailable}}
	if !r.Budget.Ceilings.Valid() || r.Budget.RingReserved < 0 || r.Budget.FrozenReserved < 0 || r.Budget.UploadAvailable < 0 ||
		r.Budget.RingReserved > r.Budget.Ceilings.RingBytes || r.Budget.FrozenReserved > r.Budget.Ceilings.FrozenBytes || r.Budget.UploadAvailable > r.Budget.Ceilings.UploadBurstBytes {
		return collector.Report{}, false
	}
	for _, m := range s.Mechanisms {
		a := collector.Availability{Mechanism: collector.Mechanism(m.Mechanism), Prerequisites: m.Prerequisites, Adapter: collector.Adapter(m.Adapter), Hook: collector.Hook(m.Hook)}
		if (a.Mechanism != collector.MechanismPacket && a.Mechanism != collector.MechanismSyscall) || (a.Adapter != collector.AdapterAvailable && a.Adapter != collector.AdapterUnavailable) ||
			(a.Hook != collector.HookNone && a.Hook != collector.HookTCX && a.Hook != collector.HookTC) || len(m.Reasons) > 16 {
			return collector.Report{}, false
		}
		for _, reason := range m.Reasons {
			if !collector.Reason(reason).Valid() {
				return collector.Report{}, false
			}
			a.Reasons = append(a.Reasons, collector.Reason(reason))
		}
		r.Mechanisms = append(r.Mechanisms, a)
	}
	for _, rc := range s.Receipts {
		v := collector.Receipt{WorkID: rc.WorkID, Sequence: rc.Sequence, Outcome: collector.Outcome(rc.Outcome), Reason: collector.Reason(rc.Reason)}
		if !text(v.WorkID, 36) || (v.Outcome != collector.OutcomeAccepted && v.Outcome != collector.OutcomeRefused) || (v.Reason != "" && !v.Reason.Valid()) {
			return collector.Report{}, false
		}
		r.Receipts = append(r.Receipts, v)
	}
	return r, true
}

func WireWork(w collector.Work) contracts.NodeWork {
	return contracts.NodeWork{ID: w.ID, Sequence: w.Sequence, Kind: string(w.Kind), NotAfter: w.NotAfter.UTC()}
}

// DomainWork keeps the kind as received: the node answers an unknown kind
// with a WorkUnknown receipt instead of dropping the item.
func DomainWork(w contracts.NodeWork) (collector.Work, bool) {
	if !text(w.ID, 36) || w.ID == "" || w.Sequence == 0 || !text(w.Kind, 32) || w.NotAfter.IsZero() {
		return collector.Work{}, false
	}
	return collector.Work{ID: w.ID, Sequence: w.Sequence, Kind: collector.WorkKind(w.Kind), NotAfter: w.NotAfter.UTC().Truncate(time.Microsecond)}, true
}
