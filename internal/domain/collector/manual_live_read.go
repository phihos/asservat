package collector

import "time"

// Exact dispatch identities for the two closed source alternatives. Manual
// fence is its original node work ID, never a fabricated observation session.
func (r LiveRead) SourceID() string {
	if r.Manual != nil {
		return r.Manual.CaptureID
	}
	return r.Binding.SourceID
}
func (r LiveRead) Fence() string {
	if r.Manual != nil {
		return r.Manual.WorkID
	}
	return r.Binding.Fence
}
func (r LiveRead) Root() string {
	if r.Manual != nil {
		return r.Manual.RootID
	}
	return r.Binding.RootID
}
func (r LiveRead) Pod() string {
	if r.Manual != nil {
		return r.Manual.PodUID
	}
	return r.Binding.PodUID
}
func (r LiveRead) Node() string {
	if r.Manual != nil {
		return r.Manual.NodeUID
	}
	return r.Binding.NodeUID
}
func (r LiveRead) Boot() string {
	if r.Manual != nil {
		return r.Manual.BootID
	}
	return r.Binding.BootID
}
func (r LiveRead) CollectorPod() string {
	if r.Manual != nil {
		return r.Manual.CollectorPodUID
	}
	return r.Binding.CollectorPodUID
}
func (r LiveRead) Epoch() string {
	if r.Manual != nil {
		return r.Manual.CollectorEpoch
	}
	return r.Binding.CollectorEpoch
}

// ManualLiveObservation contains ONLY facts the running node holder observes.
// Accepted root/attempt/action/executor/scope/expectation stay in the trusted
// request and must never gain authority by being echoed from the node.
type ManualLiveObservation struct {
	CaptureID, WorkID, PodUID, NodeUID, BootID, CollectorPodUID, CollectorEpoch string
	StartedAt, HardUntil                                                        time.Time
	ObservationKind, ObservationSessionID, ObservationFence                     string
}

func ManualObserved(m ManualLiveSource) ManualLiveObservation {
	return ManualLiveObservation{CaptureID: m.CaptureID, WorkID: m.WorkID, PodUID: m.PodUID, NodeUID: m.NodeUID, BootID: m.BootID, CollectorPodUID: m.CollectorPodUID, CollectorEpoch: m.CollectorEpoch, StartedAt: m.StartedAt, HardUntil: m.HardUntil, ObservationKind: m.ObservationKind, ObservationSessionID: m.ObservationSessionID, ObservationFence: m.ObservationFence}
}
func (o ManualLiveObservation) Valid() bool {
	for _, id := range []string{o.CaptureID, o.WorkID, o.PodUID, o.NodeUID, o.BootID, o.CollectorPodUID, o.CollectorEpoch} {
		if !validUUID(id) {
			return false
		}
	}
	if o.StartedAt.IsZero() || !o.HardUntil.After(o.StartedAt) || o.HardUntil.Sub(o.StartedAt) > MaxPacketCaptureDuration {
		return false
	}
	if o.ObservationKind == "" {
		return o.ObservationSessionID == "" && o.ObservationFence == ""
	}
	return (o.ObservationKind == "packet" || o.ObservationKind == "arguments") && validUUID(o.ObservationSessionID) && validUUID(o.ObservationFence)
}
func (o ManualLiveObservation) SameBinding(m ManualLiveSource) bool {
	expected := ManualObserved(m)
	expected.StartedAt = o.StartedAt
	expected.HardUntil = o.HardUntil
	return o == expected
}
