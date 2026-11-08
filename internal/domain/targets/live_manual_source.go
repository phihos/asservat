package targets

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// ManualLiveSource is an exact already-running finite holder. Unlike an ongoing
// source it has no policy acceptance or invented observation session. Sensitive
// captures carry their actual original permit identity; ordinary metadata does
// not. Start/end are observed once by the actual node holder, never the SQL
// preparation deadline or the live viewer's requested duration.
type ManualLiveSource struct {
	RootID, CaptureID, AttemptID, ActionID, WorkID           string
	ExecutorPodUID, ExecutorEpoch                            string
	PodUID, NodeUID, BootID, CollectorPodUID, CollectorEpoch string
	Scope, ExpectationDigest                                 [32]byte
	StartedAt, HardUntil                                     time.Time
	ObservationKind, ObservationSessionID, ObservationFence  string
}

func (m ManualLiveSource) BindingValid() bool {
	for _, id := range []string{m.RootID, m.ExecutorPodUID, m.ExecutorEpoch, m.CaptureID, m.AttemptID, m.WorkID, m.PodUID, m.NodeUID, m.BootID, m.CollectorPodUID, m.CollectorEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	if m.ActionID == "" || !identity.Text(m.ActionID, 128) || m.Scope == ([32]byte{}) || m.ExpectationDigest == ([32]byte{}) {
		return false
	}
	if m.ObservationKind == "" {
		return m.ObservationSessionID == "" && m.ObservationFence == ""
	}
	if (m.ObservationKind != "packet" && m.ObservationKind != "arguments") || !authorization.UUID(m.ObservationSessionID) || !authorization.UUID(m.ObservationFence) {
		return false
	}
	return true
}
func (m ManualLiveSource) Valid() bool {
	return m.BindingValid() && !m.StartedAt.IsZero() && m.HardUntil.After(m.StartedAt) && m.HardUntil.Sub(m.StartedAt) <= 5*time.Minute
}

// SameBinding is used only for passive holder discovery, before its original
// times are known. It cannot admit a viewer or extend a running holder.
func (m ManualLiveSource) SameBinding(other ManualLiveSource) bool {
	m.StartedAt = time.Time{}
	m.HardUntil = time.Time{}
	other.StartedAt = time.Time{}
	other.HardUntil = time.Time{}
	return m == other
}
