package targets

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// SourceSnapshotTarget is retained immutable source provenance. It is not a
// fresh PodResolution and never proves a deleted Pod still exists. Current
// initiator/executor entitlement is independently evaluated on its exact scope.
type SourceSnapshotTarget struct {
	Request                                          Request
	Pin                                              artifact.PinnedPod
	NodeUID, BootID, CollectorPodUID, CollectorEpoch string
	SourceID, Fence                                  string
	BindingDigest                                    [32]byte
}

func (s SourceSnapshotTarget) Target() authorization.Target {
	return authorization.Target{ClusterID: s.Request.ClusterID, NamespaceUID: s.Request.Namespace.UID, WorkloadUID: s.Request.Workload.UID, PodUID: s.Request.PodUID}
}
func (s SourceSnapshotTarget) Valid() bool {
	for _, id := range []string{s.NodeUID, s.BootID, s.CollectorPodUID, s.CollectorEpoch, s.SourceID, s.Fence} {
		if !authorization.UUID(id) {
			return false
		}
	}
	if s.Pin.NodeName != "" && !identity.Text(s.Pin.NodeName, 253) {
		return false
	}
	if !s.Request.Valid() || s.BindingDigest == ([32]byte{}) || s.Pin.Namespace != s.Request.Namespace.Name || s.Pin.NamespaceUID != s.Request.Namespace.UID || s.Pin.Name != s.Request.PodName || s.Pin.UID != s.Request.PodUID {
		return false
	}
	if s.Request.Workload.Kind == "Pod" {
		return s.Pin.ControllerUID == ""
	}
	return identity.Text(s.Pin.ControllerUID, 64) && (s.Request.Workload.Kind != "StatefulSet" || s.Pin.ControllerUID == s.Request.Workload.UID)
}

// SourceSnapshotResolution proves only the current authenticated process and
// bounded report of that exact retained source. Local snapshot admission still
// checks its actual current leaf/grace and capacity without arming anything.
type SourceSnapshotResolution struct {
	Original                     SourceSnapshotTarget
	Process                      PacketSourceObservation
	State                        RecorderSourceState
	ReportedAt, ReportFreshUntil time.Time
	ObservedAt, FreshUntil       time.Time
}

func (s SourceSnapshotResolution) Valid(now time.Time) bool {
	p, t, state := s.Process, s.Original, s.State
	return t.Valid() && p.Valid(now) && p.PodUID == t.Request.PodUID && p.NodeUID == t.NodeUID && p.BootID == t.BootID && p.CollectorPodUID == t.CollectorPodUID && p.CollectorEpoch == t.CollectorEpoch &&
		identity.Fresh(s.ObservedAt, s.FreshUntil, now, 5*time.Second) && !s.FreshUntil.After(p.FreshUntil) && !s.ReportedAt.After(s.ObservedAt) && s.ReportFreshUntil.After(s.ReportedAt) && now.Before(s.ReportFreshUntil) && !s.FreshUntil.After(s.ReportFreshUntil) &&
		!state.IssuedAt.IsZero() && !state.IssuedAt.After(s.ReportedAt) && state.LeafUntil.After(state.IssuedAt) && state.Credit > 0 && state.ObservedBytes >= 0 && state.ObservedBytes <= state.Credit && state.SourceID == t.SourceID && state.Fence == t.Fence && !state.Closed && state.ObservedAt.Equal(s.ReportedAt) && state.FreshUntil.Equal(s.ReportFreshUntil) &&
		(!state.Stopped || !state.SourceStoppedAt.IsZero() && !state.SnapshotUntil.IsZero() && now.Before(state.SnapshotUntil))
}
