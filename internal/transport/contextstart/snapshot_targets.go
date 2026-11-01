package contextstart

import (
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"time"
)

const queryResolveSourceSnapshot = "resolve-source-snapshot"

type SourceSnapshotTargetResolver interface {
	ResolveSourceSnapshot(context.Context, targets.SourceSnapshotTarget) (targets.SourceSnapshotResolution, error)
}

func (t Targets) ResolveSourceSnapshot(ctx context.Context, r targets.SourceSnapshotTarget) (targets.SourceSnapshotResolution, error) {
	var out targets.SourceSnapshotResolution
	if ctx == nil || ctx.Err() != nil || t.Router == nil || t.Now == nil || !r.Valid() {
		return out, targets.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	call, diagnostics := NewStreamDiagnosticContext(call)
	until, err := t.Router.Query(call, r.Request.ClusterID, queryResolveSourceSnapshot, r, &out)
	if err != nil {
		t.report("source-snapshot/"+queryStep(err, diagnostics), "")
		return targets.SourceSnapshotResolution{}, err
	}
	out, reason := checkSourceSnapshot(out, r, until, t.Now())
	if call.Err() != nil || reason != "" {
		if reason == "" {
			reason = "deadline"
		}
		t.report("source-snapshot/"+reason, "")
		return targets.SourceSnapshotResolution{}, targets.ErrUnavailable
	}
	return out, nil
}

func validateSourceSnapshot(out targets.SourceSnapshotResolution, r targets.SourceSnapshotTarget, until, now time.Time) (targets.SourceSnapshotResolution, bool) {
	out, reason := checkSourceSnapshot(out, r, until, now)
	return out, reason == ""
}

// checkSourceSnapshot returns the first failing check as a fixed label.
func checkSourceSnapshot(out targets.SourceSnapshotResolution, r targets.SourceSnapshotTarget, until, now time.Time) (targets.SourceSnapshotResolution, string) {
	out.FreshUntil = identity.Earlier(out.FreshUntil, until)
	out.Process.FreshUntil = identity.Earlier(out.Process.FreshUntil, until)
	state := out.State
	status := collector.SourceStatus{SourceID: state.SourceID, Fence: state.Fence, IssuedAt: state.IssuedAt, LeafUntil: state.LeafUntil, Credit: state.Credit, ObservedBytes: state.ObservedBytes, Closed: state.Closed, Stopped: state.Stopped, InputUnknown: state.InputUnknown, SourceStoppedAt: state.SourceStoppedAt, SnapshotUntil: state.SnapshotUntil}
	reason := ""
	switch {
	case out.Original != r:
		reason = "original"
	case !out.Valid(now) && state.Closed:
		reason = "closed"
	case !out.Valid(now) && state.Stopped:
		reason = "stopped"
	case !out.Valid(now) && (!now.Before(out.FreshUntil) || !now.Before(out.ReportFreshUntil)):
		reason = "expired"
	case !out.Valid(now):
		reason = "resolution"
	case !identity.Fresh(out.ReportedAt, out.ReportFreshUntil, now, collector.StatusStaleAfter):
		reason = "report-stale"
	case !status.Valid(out.ReportedAt):
		reason = "status"
	}
	if reason != "" {
		return targets.SourceSnapshotResolution{}, reason
	}
	return out, ""
}

const opResolveSourceSnapshot = "resolve-source-snapshot"

func (h *HubOperations) ResolveSourceSnapshot(ctx context.Context, r targets.SourceSnapshotTarget) (targets.SourceSnapshotResolution, error) {
	var out targets.SourceSnapshotResolution
	err := h.call(ctx, opResolveSourceSnapshot, r, &out)
	return out, err
}
func (s *regionalSession) resolveSourceSnapshot(ctx context.Context, raw []byte) (any, error) {
	var r targets.SourceSnapshotTarget
	if err := decodeOperationBody(raw, &r); err != nil {
		return nil, err
	}
	resolver, ok := s.local.Targets.(SourceSnapshotTargetResolver)
	if !ok || !r.Valid() || r.Target() != s.work.Target || s.resolved != nil || s.packetSource != nil || s.snapshotTarget != nil {
		return nil, targets.ErrDenied
	}
	out, err := resolver.ResolveSourceSnapshot(ctx, r)
	if err != nil {
		return nil, err
	}
	if out.Original != r || !out.Valid(s.local.Now()) {
		return nil, targets.ErrDenied
	}
	s.snapshotTarget = &out
	return out, nil
}
