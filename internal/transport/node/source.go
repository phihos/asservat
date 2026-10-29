package node

import (
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
)

func WireSourceBinding(b collector.SourceBinding) contracts.NodeSourceBinding {
	program := ""
	if b.ProgramDigest != [32]byte{} {
		program = hex.EncodeToString(b.ProgramDigest[:])
	}
	return contracts.NodeSourceBinding{RootID: b.RootID, PolicyUID: b.PolicyUID, AcceptanceID: b.AcceptanceID, SourceID: b.SourceID, Fence: b.Fence, ActionID: b.ActionID, PodUID: b.PodUID, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch, Scope: hex.EncodeToString(b.Scope[:]), ExpectationDigest: hex.EncodeToString(b.ExpectationDigest[:]), ProgramDigest: program, ResourceDigest: hex.EncodeToString(b.ResourceDigest[:])}
}
func DomainSourceBinding(w contracts.NodeSourceBinding) (collector.SourceBinding, bool) {
	b := collector.SourceBinding{RootID: w.RootID, PolicyUID: w.PolicyUID, AcceptanceID: w.AcceptanceID, SourceID: w.SourceID, Fence: w.Fence, ActionID: w.ActionID, PodUID: w.PodUID, NodeUID: w.NodeUID, BootID: w.BootID, CollectorPodUID: w.CollectorPodUID, CollectorEpoch: w.CollectorEpoch}
	var ok bool
	if b.Scope, ok = digestHex(w.Scope); !ok {
		return b, false
	}
	if b.ExpectationDigest, ok = digestHex(w.ExpectationDigest); !ok {
		return b, false
	}
	if b.ProgramDigest, ok = digestHex(w.ProgramDigest); !ok {
		return b, false
	}
	if b.ResourceDigest, ok = digestHex(w.ResourceDigest); !ok {
		return b, false
	}
	return b, b.Valid()
}
func WirePacketSource(s collector.PacketSource) contracts.NodePacketSource {
	p, r := s.Permit, s.Ring
	w := contracts.NodePacketSource{Permit: contracts.NodeSourcePermit{Binding: WireSourceBinding(p.Binding), StartedAt: p.StartedAt.UTC(), HardUntil: p.HardUntil.UTC(), StartBy: p.StartBy.UTC(), IssuedAt: p.IssuedAt.UTC(), DispatchUntil: p.DispatchUntil.UTC(), LeafUntil: p.LeafUntil.UTC(), Credit: p.Credit, BytesPerSecond: p.BytesPerSecond}, Program: make([]contracts.NodeBPFInstruction, len(s.Program)), Ring: contracts.NodeSourceRingLimits{MaxAgeNanos: int64(r.MaxAge), MaxBytes: r.MaxBytes, SegmentBytes: r.SegmentBytes, MaxFrozenBytes: r.MaxFrozenBytes, MaxSegments: r.MaxSegments, MaxConcurrentSnapshots: r.MaxConcurrentSnapshots}}
	limits := s.Resources.Node
	w.ResourcePolicyUID = s.Resources.PolicyUID
	w.NodeLimits = WireCeilings(collector.Ceilings{SourceLimits: limits.SourceLimits, RingBytes: limits.RingBytes, FrozenBytes: limits.FrozenBytes, UploadBytesPerSecond: limits.UploadBytesPerSecond, UploadBurstBytes: limits.UploadBurstBytes})
	w.WorkloadLimits = contracts.NodeSourceLimits{MaxActiveSources: s.Resources.Workload.MaxActiveSources, InputBytesPerSecond: s.Resources.Workload.InputBytesPerSecond, InputBurstBytes: s.Resources.Workload.InputBurstBytes}
	for i, ins := range s.Program {
		w.Program[i] = contracts.NodeBPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	return w
}
func DomainPacketSource(w contracts.NodePacketSource) (collector.PacketSource, bool) {
	p, r := w.Permit, w.Ring
	b, ok := DomainSourceBinding(p.Binding)
	if !ok || len(w.Program) > planning.MaxFilterInstructions {
		return collector.PacketSource{}, false
	}
	s := collector.PacketSource{Permit: collector.SourcePermit{Binding: b, StartedAt: p.StartedAt.UTC(), HardUntil: p.HardUntil.UTC(), StartBy: p.StartBy.UTC(), IssuedAt: p.IssuedAt.UTC(), DispatchUntil: p.DispatchUntil.UTC(), LeafUntil: p.LeafUntil.UTC(), Credit: p.Credit, BytesPerSecond: p.BytesPerSecond}, Ring: collector.SourceRingLimits{MaxAge: time.Duration(r.MaxAgeNanos), MaxBytes: r.MaxBytes, SegmentBytes: r.SegmentBytes, MaxFrozenBytes: r.MaxFrozenBytes, MaxSegments: r.MaxSegments, MaxConcurrentSnapshots: r.MaxConcurrentSnapshots}, Program: make([]planning.BPFInstruction, len(w.Program))}
	for i, ins := range w.Program {
		s.Program[i] = planning.BPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	limits := DomainCeilings(w.NodeLimits)
	s.Resources = collector.SourceResources{PolicyUID: w.ResourcePolicyUID, Node: collector.PolicyLimits{SourceLimits: limits.SourceLimits, RingBytes: limits.RingBytes, FrozenBytes: limits.FrozenBytes, UploadBytesPerSecond: limits.UploadBytesPerSecond, UploadBurstBytes: limits.UploadBurstBytes}, Workload: collector.SourceLimits{MaxActiveSources: w.WorkloadLimits.MaxActiveSources, InputBytesPerSecond: w.WorkloadLimits.InputBytesPerSecond, InputBurstBytes: w.WorkloadLimits.InputBurstBytes}}
	return s, s.Valid() && deliveryapp.SourceResourcesDigest(s.Resources) == s.Permit.Binding.ResourceDigest
}
