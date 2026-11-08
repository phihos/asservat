package live

import "asservat.local/asservat/internal/domain/collector"

// BindManualLiveReply matches node-observed facts to the exact trusted original
// request, then restores ONLY its non-observed accepted provenance. This pure
// helper supplies no authority and cannot renew any observed original bound.
func BindManualLiveReply(r collector.LiveRead, out NodeReply) (NodeReply, error) {
	if r.Manual == nil {
		if out.Manual != nil || out.ObservedManual != nil {
			return NodeReply{}, ErrDenied
		}
		return out, nil
	}
	if !r.Valid() || (out.Manual == nil) == (out.ObservedManual == nil) {
		return NodeReply{}, ErrDenied
	}
	var observed collector.ManualLiveObservation
	if out.Manual != nil {
		if !out.Manual.SameBinding(*r.Manual) {
			return NodeReply{}, ErrDenied
		}
		observed = collector.ManualObserved(*out.Manual)
	} else {
		observed = *out.ObservedManual
	}
	if !observed.Valid() || !observed.SameBinding(*r.Manual) || out.SourceID != observed.CaptureID || out.Fence != observed.WorkID || out.BootID != observed.BootID || r.Head && len(out.Rows) != 0 {
		return NodeReply{}, ErrDenied
	}
	expectedClock := "monotonic"
	if r.Projection == Syscall {
		expectedClock = "boottime"
	}
	if out.Clock != expectedClock || out.Sample <= 0 {
		return NodeReply{}, ErrDenied
	}
	if !r.Inspect && (!observed.StartedAt.Equal(r.Manual.StartedAt) || !observed.HardUntil.Equal(r.Manual.HardUntil)) {
		return NodeReply{}, ErrDenied
	}
	source := *r.Manual
	source.StartedAt = observed.StartedAt
	source.HardUntil = observed.HardUntil
	if !source.Valid() {
		return NodeReply{}, ErrDenied
	}
	out.Manual = &source
	out.ObservedManual = nil
	return out, nil
}
