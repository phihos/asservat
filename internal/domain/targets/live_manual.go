package targets

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// ManualLiveTarget comes from the original accepted finite work and started
// execution. It is not a viewer-selected node, source permit or new dispatch.
type ManualLiveTarget struct {
	RootID, CaptureID, AttemptID, ActionID                  string
	Scope, ExpectationDigest                                artifact.Digest
	Target                                                  authorization.Target
	Executor                                                execution.APIProcessBinding
	WriteUntil                                              time.Time
	Projection                                              string
	ObservationKind, ObservationSessionID, ObservationFence string
}

func (t ManualLiveTarget) Valid() bool {
	if t.ObservationKind == "" {
		if t.ObservationSessionID != "" || t.ObservationFence != "" {
			return false
		}
	} else if (t.ObservationKind != "packet" && t.ObservationKind != "arguments") || !authorization.UUID(t.ObservationSessionID) || !authorization.UUID(t.ObservationFence) {
		return false
	}
	return authorization.UUID(t.RootID) && authorization.UUID(t.CaptureID) && authorization.UUID(t.AttemptID) && identity.Text(t.ActionID, 128) && t.ActionID != "" && t.Scope != (artifact.Digest{}) && t.ExpectationDigest != (artifact.Digest{}) && t.Target.Valid() && t.Executor.Valid() && t.Executor.ClusterID == t.Target.ClusterID && !t.WriteUntil.IsZero() && (t.Projection == "packetMetadata" || t.Projection == "syscallMetadata" || t.Projection == "httpHeaders")
}

type ManualLiveResolution struct {
	Unavailable            bool
	Original               ManualLiveTarget
	Source                 ManualLiveSource
	ObservedAt, FreshUntil time.Time
}

func (r ManualLiveResolution) Valid(now time.Time) bool {
	t, m := r.Original, r.Source
	if !t.Valid() || !identity.Fresh(r.ObservedAt, r.FreshUntil, now, 5*time.Second) || r.FreshUntil.After(t.WriteUntil) {
		return false
	}
	if r.Unavailable {
		return m == (ManualLiveSource{})
	}
	return m.Valid() && m.RootID == t.RootID && m.CaptureID == t.CaptureID && m.AttemptID == t.AttemptID && m.ActionID == t.ActionID && m.Scope == [32]byte(t.Scope) && m.ExpectationDigest == [32]byte(t.ExpectationDigest) && m.PodUID == t.Target.PodUID && m.ExecutorPodUID == t.Executor.PodUID && m.ExecutorEpoch == t.Executor.ProcessEpoch && m.ObservationKind == t.ObservationKind && m.ObservationSessionID == t.ObservationSessionID && m.ObservationFence == t.ObservationFence && !m.HardUntil.After(t.WriteUntil) && !now.Before(m.StartedAt) && now.Before(m.HardUntil) && !r.FreshUntil.After(m.HardUntil)
}
