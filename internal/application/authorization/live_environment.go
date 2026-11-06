package authorization

import (
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/privacy"
	"context"
	"fmt"
	"time"
)

// CurrentLiveEnvironment reuses the existing protected delivery configuration
// and recovery reader. Live opt-in is independent from native-download clients.
type CurrentLiveEnvironment struct {
	RootID, InstallationID string
	// AcceptedRoot pins the same protected config snapshot used for SQL accounting.
	// Numeric root changes require a new guarded process; scoped lowerings remain current.
	AcceptedRoot privacy.LiveRootLimits
	Policies     DownloadPolicyReader
	Recovery     DownloadRecoveryReader
	Now          func() time.Time
}

func (s CurrentLiveEnvironment) LiveSourceRead(ctx context.Context, source live.Source, projection string, actor identity.Principal) (LiveEnvironmentDecision, error) {
	out, e := s.LiveSourceReads(ctx, []live.Source{source}, projection, actor)
	if e != nil || len(out) != 1 {
		return LiveEnvironmentDecision{}, live.ErrDenied
	}
	return out[0], nil
}

// LiveSourceReads shares only source-independent policy/recovery observations
// within this phase. A later phase calls it again; no authority is cached.
func (s CurrentLiveEnvironment) LiveSourceReads(ctx context.Context, sources []live.Source, projection string, actor identity.Principal) ([]LiveEnvironmentDecision, error) {
	if ctx == nil || ctx.Err() != nil || s.Policies == nil || s.Recovery == nil || s.Now == nil || !actor.Valid() || len(sources) < 1 || len(sources) > 100 {
		return nil, fmt.Errorf("%w: live environment input", live.ErrDenied)
	}
	until := s.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	p, e := s.Policies.DownloadPolicy(call)
	if e != nil || p.RootID != s.RootID || p.InstallationID != s.InstallationID || p.LiveRead == nil || !s.AcceptedRoot.Valid() || p.LiveRead.Root != s.AcceptedRoot {
		return nil, fmt.Errorf("%w: live settings root", live.ErrDenied)
	}
	paths := make([]privacy.DownloadPath, len(sources))
	limits := make([]privacy.LiveLimits, len(sources))
	for n, source := range sources {
		if source.Root() != s.RootID {
			return nil, fmt.Errorf("%w: live environment source-root", live.ErrDenied)
		}
		var reason string
		paths[n], limits[n], reason = p.SelectLiveReason(actor, source.Target, projection, s.Now())
		if reason != "" {
			return nil, fmt.Errorf("%w: live settings %s", live.ErrDenied, reason)
		}
	}
	until = identity.Earlier(until, p.FreshUntil)
	bounded, cancel := context.WithDeadline(call, until)
	defer cancel()
	recovery, e := s.Recovery.RecoveryState(bounded)
	if e != nil || !recovery.Valid(s.Now()) || recovery.InstallationID != s.InstallationID || recovery.IssuerEpoch != p.RecoveryEpoch {
		return nil, fmt.Errorf("%w: live recovery", live.ErrDenied)
	}
	until = identity.Earlier(until, recovery.FreshUntil)
	final, stopFinal := context.WithDeadline(bounded, until)
	defer stopFinal()
	last, e := s.Policies.DownloadPolicy(final)
	if e != nil || last.RootID != p.RootID || last.InstallationID != p.InstallationID || last.RecoveryEpoch != p.RecoveryEpoch || last.Revision != p.Revision || last.ProtectionDigest != p.ProtectionDigest {
		return nil, fmt.Errorf("%w: live environment last-policy", live.ErrDenied)
	}
	for n, source := range sources {
		path, limit, ok := last.SelectLive(actor, source.Target, projection, s.Now())
		if !ok || path != paths[n] || limit != limits[n] {
			return nil, fmt.Errorf("%w: live environment last-select", live.ErrDenied)
		}
	}
	until = identity.Earlier(until, last.FreshUntil)
	lastRecovery, e := s.Recovery.RecoveryState(final)
	if e != nil || !lastRecovery.Valid(s.Now()) || lastRecovery.InstallationID != recovery.InstallationID || lastRecovery.IssuerEpoch != recovery.IssuerEpoch || lastRecovery.Revision != recovery.Revision {
		return nil, fmt.Errorf("%w: live environment last-recovery", live.ErrDenied)
	}
	until = identity.Earlier(until, lastRecovery.FreshUntil)
	if final.Err() != nil || !s.Now().Before(until) {
		return nil, fmt.Errorf("%w: live environment deadline", live.ErrDenied)
	}
	out := make([]LiveEnvironmentDecision, len(sources))
	for n, l := range limits {
		out[n] = LiveEnvironmentDecision{ValidUntil: until, Projections: append([]string(nil), p.LiveRead.Projections...), Limits: live.Limits{Duration: l.Duration, Output: l.Output, Rate: l.Rate, Rows: l.Rows, Buffer: l.Buffer, RowAge: l.RowAge, Replay: l.Replay}}
	}
	return out, nil
}
