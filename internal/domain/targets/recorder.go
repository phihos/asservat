package targets

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// RecorderRequest asks the region whether the node collector on the node of
// one resolved Pod currently offers the packet recorder (ADR-248). It names
// the Pod by its resolved request and pin; the region reads the Pod's node
// itself.
type RecorderRequest struct {
	Target Request
	Pin    artifact.PinnedPod
}

func (r RecorderRequest) Valid() bool {
	return r.Target.Valid() && r.Pin.UID == r.Target.PodUID && r.Pin.Name == r.Target.PodName && r.Pin.NamespaceUID == r.Target.Namespace.UID && r.Pin.Namespace == r.Target.Namespace.Name
}

// Closed recorder answers. Only RecorderAvailable allows a manual packet
// capture to be accepted; the connector checks the node again before work.
const (
	RecorderAvailable   = "available"
	RecorderUnavailable = "unavailable" // no current collector report offers it
	RecorderNoNode      = "noNode"      // the Pod is not running on a node
)

// PacketSourceObservation identifies one whole-Pod recorder incarnation. Its
// interval intersects the original Pod and authenticated node-report intervals.
// It is target observation data, never collection or grant authority.
type PacketSourceObservation struct {
	PodUID, NodeUID, BootID, CollectorPodUID, CollectorEpoch string
	ObservedAt, FreshUntil                                   time.Time
}

func (s PacketSourceObservation) Valid(now time.Time) bool {
	for _, value := range []string{s.PodUID, s.NodeUID, s.BootID, s.CollectorPodUID, s.CollectorEpoch} {
		if len(value) == 0 || len(value) > 128 {
			return false
		}
	}
	return !s.ObservedAt.IsZero() && !s.ObservedAt.After(now) && s.FreshUntil.After(s.ObservedAt) && now.Before(s.FreshUntil)
}

type RecorderAnswer struct {
	Outcome string
	Source  *PacketSourceObservation `json:",omitempty"`
}

func (a RecorderAnswer) Valid() bool {
	return a.Outcome == RecorderAvailable || a.Outcome == RecorderUnavailable || a.Outcome == RecorderNoNode
}

// RecorderResolution combines one exact API target observation and its transient
// packet availability. It does not add node execution identity to the API pin.
type RecorderResolution struct {
	Target   PodResolution
	Recorder RecorderAnswer
}

func (r RecorderResolution) Valid(now time.Time) bool {
	return r.Target.ExecutionClass == artifact.ContextAPIExecution && r.Target.Valid(now) && r.Recorder.Valid()
}

// ValidSource is the separate exact-source preflight for a sensitive dispatch.
// Source freshness must not shorten ordinary metadata availability or its API pin.
// Passing this check still supplies no collection or grant authority.
func (r RecorderResolution) ValidSource(now time.Time) bool {
	s := r.Recorder.Source
	return r.Valid(now) && s != nil && r.Recorder.Outcome == RecorderAvailable && s.PodUID == r.Target.Pin.UID && s.Valid(now) && !s.ObservedAt.Before(r.Target.ObservedAt) && !s.FreshUntil.After(r.Target.FreshUntil)
}
