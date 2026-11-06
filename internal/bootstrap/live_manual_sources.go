package bootstrap

import (
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"time"
)

type liveManualHolders interface {
	ResolveManualLive(context.Context, []targets.ManualLiveTarget) ([]targets.ManualLiveResolution, error)
}
type liveManualCatalog struct {
	root     string
	works    executionapp.LiveManualWorks
	recovery authapp.DownloadRecoveryReader
	holders  liveManualHolders
	now      func() time.Time
}

func (s liveManualCatalog) configured() bool {
	return authorization.UUID(s.root) && s.works != nil && s.recovery != nil && s.holders != nil && s.now != nil
}
func (s liveManualCatalog) target(ctx context.Context, id string) (authorization.Target, error) {
	if !s.configured() {
		return authorization.Target{}, live.ErrUnavailable
	}
	return s.works.LiveManualTarget(ctx, id)
}
func (s liveManualCatalog) read(ctx context.Context, refs []live.SourceReference) ([]authapp.LiveSourceRecord, error) {
	if !s.configured() || len(refs) < 1 || len(refs) > 16 {
		return nil, live.ErrInvalid
	}
	recovery, e := s.recovery.RecoveryState(ctx)
	if e != nil || !recovery.Valid(s.now()) {
		return nil, live.ErrUnavailable
	}
	ids := make([]string, len(refs))
	for n, r := range refs {
		if r.Kind != "manualSession" || !r.Target.Valid() {
			return nil, live.ErrInvalid
		}
		ids[n] = r.ID
	}
	rows, e := s.works.ReadLiveManualWork(ctx, ids, recovery)
	if e != nil || len(rows) != len(refs) {
		return nil, live.ErrUnavailable
	}
	out, e := s.records(ctx, rows)
	if e != nil || len(out) != len(refs) {
		return nil, live.ErrUnavailable
	}
	for n, r := range out {
		if r.Source.ID() != refs[n].ID || r.Source.Target != refs[n].Target {
			return nil, live.ErrDenied
		}
	}
	return out, nil
}
func (s liveManualCatalog) list(ctx context.Context, target authorization.WorkloadTarget, cursor string, limit int) ([]authapp.LiveSourceRecord, string, error) {
	if !s.configured() {
		return nil, "", live.ErrUnavailable
	}
	recovery, e := s.recovery.RecoveryState(ctx)
	if e != nil || !recovery.Valid(s.now()) {
		return nil, "", live.ErrUnavailable
	}
	rows, next, e := s.works.ListLiveManualWork(ctx, target, cursor, limit, recovery)
	if e != nil {
		return nil, "", e
	}
	out, e := s.records(ctx, rows)
	return out, next, e
}
func manualProjection(e artifact.ContextExpectation) string {
	if e.Recording == nil || e.Snapshot != nil {
		return ""
	}
	switch e.NativeType {
	case artifact.PCAPNGArtifact, artifact.RawPCAPNGArtifact:
		return live.Packet
	case artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact:
		return live.Syscall
	case artifact.HTTPHeadersArtifact:
		return live.HTTP
	}
	return ""
}
func (s liveManualCatalog) records(ctx context.Context, rows []executionapp.LiveManualWork) ([]authapp.LiveSourceRecord, error) {
	if len(rows) > 100 {
		return nil, live.ErrInvalid
	}
	out := make([]authapp.LiveSourceRecord, 0, len(rows))
	for first := 0; first < len(rows); first += 16 {
		last := min(first+16, len(rows))
		originals := make([]targets.ManualLiveTarget, last-first)
		for n, r := range rows[first:last] {
			w, e := r.Work, r.Work.Accepted.Expectation
			projection := manualProjection(e)
			if projection == "" || w.CancellationRequested || w.SourceBinding != nil || w.Actor.Kind != identity.Human || !w.Actor.Valid() || r.Execution.RootID != s.root || r.Execution.Phase != "started" || !r.Execution.Valid() || e.Validate() != nil || !identity.Fresh(r.ObservedAt, r.FreshUntil, s.now(), 5*time.Second) {
				return nil, live.ErrDenied
			}
			t := targets.ManualLiveTarget{RootID: s.root, CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ActionID: e.ActionID, Scope: w.Accepted.ScopeDigest, ExpectationDigest: evidence.ContextExpectationDigest(e), Target: authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}, Executor: r.Execution.Process, WriteUntil: e.Registration.WriteUntil, Projection: projection}
			if b := r.Observation; b != nil {
				if r.Arguments != nil || !b.Valid() || b.CaptureID != t.CaptureID || b.ActionID != t.ActionID || b.ExpectationDigest != [32]byte(t.ExpectationDigest) {
					return nil, live.ErrDenied
				}
				t.ObservationKind, t.ObservationSessionID, t.ObservationFence = "packet", b.SessionID, b.Fence
			}
			if b := r.Arguments; b != nil {
				if !b.Valid() || b.CaptureID != t.CaptureID || b.ActionID != t.ActionID || b.ExpectationDigest != [32]byte(t.ExpectationDigest) {
					return nil, live.ErrDenied
				}
				t.ObservationKind, t.ObservationSessionID, t.ObservationFence = "arguments", b.SessionID, b.Fence
			}
			if !t.Valid() {
				return nil, live.ErrDenied
			}
			originals[n] = t
		}
		resolved, e := s.holders.ResolveManualLive(ctx, originals)
		if e != nil || len(resolved) != len(originals) {
			return nil, live.ErrUnavailable
		}
		for n, r := range resolved {
			if r.Original != originals[n] || !r.Valid(s.now()) {
				return nil, live.ErrUnavailable
			}
			if r.Unavailable {
				continue
			}
			w := rows[first+n]
			m := r.Source
			if b := w.Observation; b != nil && (b.NodeUID != m.NodeUID || b.BootID != m.BootID || b.CollectorPodUID != m.CollectorPodUID || b.CollectorEpoch != m.CollectorEpoch) {
				return nil, live.ErrDenied
			}
			if b := w.Arguments; b != nil && (b.NodeUID != m.NodeUID || b.BootID != m.BootID || b.CollectorPodUID != m.CollectorPodUID || b.CollectorEpoch != m.CollectorEpoch) {
				return nil, live.ErrDenied
			}
			source := live.Source{RootID: s.root, Manual: &m, Target: r.Original.Target, OwnerKind: "manualSession", OwnerID: m.CaptureID, State: "Ready", SaveVia: "captureOutcome", Projections: []string{r.Original.Projection}, Blockers: []string{}, HardUntil: m.HardUntil, LeaseUntil: m.HardUntil, PrivacyUntil: identity.Earlier(identity.Earlier(m.HardUntil, r.Original.WriteUntil), w.Work.Accepted.Deadline)}
			// SQL/holder freshness bounds this read, not the reference's original source
			// privacy end. The reference is clipped by immutable source/write limits.

			if !source.Valid(s.now()) {
				return nil, live.ErrDenied
			}
			out = append(out, authapp.LiveSourceRecord{Source: source, Audience: append([]artifact.AudienceAssignment(nil), w.Work.Accepted.Expectation.Audience...), Executor: w.Work.Actor, ObservedAt: w.ObservedAt, ValidUntil: identity.Earlier(w.FreshUntil, r.FreshUntil)})
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return out, nil
}
