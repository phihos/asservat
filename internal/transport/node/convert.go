// Package node is the HTTP transport of the private node work channel
// (ADR-246, I-02): the connector's handler and the collector's client. It
// converts between the closed wire DTOs and the collector domain values; the
// delivery package owns all channel state.
package node

import (
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
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
	return contracts.NodeCeilings{MaxActiveSources: c.MaxActiveSources, InputBytesPerSecond: c.InputBytesPerSecond, InputBurstBytes: c.InputBurstBytes, RingBytes: c.RingBytes, FrozenBytes: c.FrozenBytes, UploadBytesPerSecond: c.UploadBytesPerSecond, UploadBurstBytes: c.UploadBurstBytes}
}

func DomainCeilings(c contracts.NodeCeilings) collector.Ceilings {
	return collector.Ceilings{SourceLimits: collector.SourceLimits{MaxActiveSources: c.MaxActiveSources, InputBytesPerSecond: c.InputBytesPerSecond, InputBurstBytes: c.InputBurstBytes}, RingBytes: c.RingBytes, FrozenBytes: c.FrozenBytes, UploadBytesPerSecond: c.UploadBytesPerSecond, UploadBurstBytes: c.UploadBurstBytes}
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
		a := collector.Availability{Mechanism: collector.Mechanism(m.Mechanism), Prerequisites: m.Prerequisites, Adapter: collector.Adapter(m.Adapter), Hook: collector.Hook(m.Hook), Reasons: []collector.Reason{}}
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
	out := contracts.NodeWork{ID: w.ID, Sequence: w.Sequence, Kind: string(w.Kind), NotAfter: w.NotAfter.UTC()}
	if p := w.Packet; p != nil {
		c := &contracts.NodePacketCapture{CaptureID: p.CaptureID, PodUID: p.PodUID, Program: make([]contracts.NodeBPFInstruction, len(p.Program)),
			DurationMillis: p.Duration.Milliseconds(), MaxBytes: p.MaxBytes}
		for i, ins := range p.Program {
			c.Program[i] = contracts.NodeBPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
		}
		if p.ProgramDigest != ([32]byte{}) {
			c.ProgramDigest = hex.EncodeToString(p.ProgramDigest[:])
		}
		if p.Observation != nil {
			c.Observation = wireObservation(*p.Observation)
		}
		out.PacketCapture = c
	}
	return out
}

func digestHex(s string) ([32]byte, bool) {
	var d [32]byte
	if s == "" {
		return d, true
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return d, false
	}
	copy(d[:], b)
	return d, d != [32]byte{}
}

// DomainWork keeps the kind as received: the node answers an unknown kind
// with a WorkUnknown receipt instead of dropping the item. A payload that is
// not exactly a valid packet capture is kept invalid for the same answer.
func DomainWork(w contracts.NodeWork) (collector.Work, bool) {
	if !text(w.ID, 36) || w.ID == "" || w.Sequence == 0 || !text(w.Kind, 32) || w.NotAfter.IsZero() {
		return collector.Work{}, false
	}
	out := collector.Work{ID: w.ID, Sequence: w.Sequence, Kind: collector.WorkKind(w.Kind), NotAfter: w.NotAfter.UTC().Truncate(time.Microsecond)}
	if c := w.PacketCapture; c != nil {
		// An unusable payload stays an invalid item, answered WorkUnknown.
		if len(c.Program) > planning.MaxFilterInstructions || c.DurationMillis < 0 || c.DurationMillis > collector.MaxPacketCaptureDuration.Milliseconds() || !text(c.CaptureID, 36) || !text(c.PodUID, 36) {
			out.Packet = &collector.PacketCapture{}
			return out, true
		}
		p := &collector.PacketCapture{CaptureID: c.CaptureID, PodUID: c.PodUID, Program: make([]planning.BPFInstruction, len(c.Program)),
			Duration: time.Duration(c.DurationMillis) * time.Millisecond, MaxBytes: c.MaxBytes}
		for i, ins := range c.Program {
			p.Program[i] = planning.BPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
		}
		d, ok := digestHex(c.ProgramDigest)
		if !ok && c.ProgramDigest != "" {
			out.Packet = &collector.PacketCapture{}
			return out, true
		}
		p.ProgramDigest = d
		if c.Observation != nil {
			permit, valid := domainObservation(c.Observation)
			if !valid {
				out.Packet = &collector.PacketCapture{}
				return out, true
			}
			p.Observation = permit
			// Preserve the original finite cutoff exactly; metadata keeps its legacy normalization.
			out.NotAfter = w.NotAfter.UTC()
		}
		out.Packet = p
	}
	return out, true
}

// WirePacketResult heads a capture upload.
func WirePacketResult(epoch string, r collector.PacketResult) contracts.NodePacketResult {
	out := contracts.NodePacketResult{Format: contracts.NodeCaptureFormat, Epoch: epoch, WorkID: r.WorkID, CaptureID: r.CaptureID, StartedAt: r.StartedAt.UTC(), EndedAt: r.EndedAt.UTC(),
		Seen: r.Seen, Retained: r.Retained, Filtered: r.Filtered, Unsupported: r.Unsupported, Fragment: r.Fragment, Extension: r.Extension, Malformed: r.Malformed,
		OutputFull: r.OutputFull, LostSamples: r.LostSamples, WireBytes: r.WireBytes, CapturedBytes: r.CapturedBytes, Snaplen: r.Snaplen, EngineVersion: r.EngineVersion, Failure: string(r.Failure)}
	if r.ProgramDigest != ([32]byte{}) {
		out.ProgramDigest = hex.EncodeToString(r.ProgramDigest[:])
	}
	return out
}

// DomainPacketResult validates an upload header.
func DomainPacketResult(w contracts.NodePacketResult) (collector.PacketResult, bool) {
	d, ok := digestHex(w.ProgramDigest)
	if w.Format != contracts.NodeCaptureFormat || !ok && w.ProgramDigest != "" || !text(w.EngineVersion, 64) {
		return collector.PacketResult{}, false
	}
	r := collector.PacketResult{WorkID: w.WorkID, CaptureID: w.CaptureID, StartedAt: w.StartedAt.UTC().Truncate(time.Microsecond), EndedAt: w.EndedAt.UTC().Truncate(time.Microsecond),
		Seen: w.Seen, Retained: w.Retained, Filtered: w.Filtered, Unsupported: w.Unsupported, Fragment: w.Fragment, Extension: w.Extension, Malformed: w.Malformed,
		OutputFull: w.OutputFull, LostSamples: w.LostSamples, WireBytes: w.WireBytes, CapturedBytes: w.CapturedBytes, Snaplen: w.Snaplen, EngineVersion: w.EngineVersion, ProgramDigest: d, Failure: collector.Reason(w.Failure)}
	return r, r.Valid()
}
