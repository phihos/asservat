package authorization

import (
	"context"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// ExplainTargets resolves a named workload to one current whole-pod target,
// exactly as preview_capture does.
type ExplainTargets interface {
	ResolveWorkload(context.Context, targets.WorkloadRequest) (targets.PodResolution, error)
}

type ExplainRecovery interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}

// AccessExplainer answers explain_access (ADR-234) for the calling principal
// only. It reads the same target resolution and permission projection as the
// capture and read paths and runs the real evaluator; it writes nothing and
// returns no authority.
type AccessExplainer struct {
	InstallationID string
	Targets        ExplainTargets
	Permissions    ProjectionReader
	Recovery       ExplainRecovery
	Now            func() time.Time
}

// Explain returns the explanation and the reply's metadata deadline. Errors
// are reserved for an invalid request or an unusable caller identity.
func (s AccessExplainer) Explain(ctx context.Context, current identities.CurrentIdentity, ref targets.WorkloadRequest, op value.Operation) (value.Explanation, time.Time, error) {
	var zero value.Explanation
	if ctx == nil || current == nil || s.Targets == nil || s.Permissions == nil || s.Recovery == nil || s.Now == nil || !value.UUID(s.InstallationID) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	if !ref.Valid() || !op.Valid() {
		return zero, time.Time{}, value.ErrExplainInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, time.Time{}, identity.ErrDenied
	}
	until := i.ValidUntil
	unavailable := value.Explanation{Decision: value.Indeterminate, Unmet: value.UnmetServiceUnavailable}
	// Recovery and the permission store are installation-wide conditions,
	// so reporting them reveals nothing about the named target.
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || recovery.InstallationID != s.InstallationID || !recovery.Valid(s.Now()) {
		return s.final(ctx, current, i, unavailable, until)
	}
	until = identity.Earlier(until, recovery.FreshUntil)
	resolved, err := s.Targets.ResolveWorkload(ctx, ref)
	if err != nil || !resolved.Valid(s.Now()) {
		// Absent, unobservable and unauthorized targets look the same.
		return s.final(ctx, current, i, value.Undisclosed(), until)
	}
	target := resolved.Target()
	p, err := s.Permissions.Permissions(ctx, target)
	if err != nil {
		return s.final(ctx, current, i, unavailable, until)
	}
	out := value.Explain(i, p, op, target, s.Now())
	return s.final(ctx, current, i, out, until)
}

// final rechecks the caller after the blocking reads, as every operation does.
func (s AccessExplainer) final(ctx context.Context, current identities.CurrentIdentity, i identity.Identity, out value.Explanation, until time.Time) (value.Explanation, time.Time, error) {
	fresh, err := current.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy || !fresh.Valid(s.Now()) {
		return value.Explanation{}, time.Time{}, identity.ErrDenied
	}
	until = identity.Earlier(until, fresh.ValidUntil)
	if ctx.Err() != nil || !s.Now().Before(until) {
		return value.Explanation{}, time.Time{}, identity.ErrUnavailable
	}
	return out, until, nil
}
