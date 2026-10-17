package capture

import (
	"context"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// CheckDiagnostic passively checks the one qualified diagnostic for a named
// authorized workload. Unlike Preview, catalog discovery consumes no draft slot,
// generates no IDs and reserves no evidence or work capacity.
func (s ContextInvestigation) CheckDiagnostic(ctx context.Context, source identities.CurrentIdentity, targetRef targets.WorkloadRequest) (time.Time, error) {
	if !s.configured() || ctx == nil || source == nil || ctx.Err() != nil {
		return time.Time{}, value.ErrUnavailable
	}
	if !targetRef.Valid() {
		return time.Time{}, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := s.Now()
	i, err := source.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return time.Time{}, value.ErrDenied
	}
	recovery, err := s.currentRecovery(ctx)
	if err != nil {
		return time.Time{}, err
	}
	target, err := s.Targets.ResolveWorkload(ctx, targetRef)
	if err != nil {
		return time.Time{}, err
	}
	f, err := s.facts(ctx, source, i.Principal, value.ContextIntent{Target: targetRef, Diagnostic: value.ContextDiagnosticName}, target, started.UTC().Truncate(time.Microsecond))
	if err != nil {
		return time.Time{}, err
	}
	current := s.Eligibility.ContextEligibilityCurrent(ctx, source, target.Target())
	if !current.Eligible || current.Principal != i.Principal || current.Target != target.Target() || !current.VerifiedIdentity.Valid(s.Now()) || !s.Now().Before(current.ValidUntil) || !s.factsCurrent(f, s.Now()) || !recovery.Valid(s.Now()) || s.Now().Before(started) {
		return time.Time{}, value.ErrDenied
	}
	_, err = s.currentIdentity(ctx, source, i.Principal, i.ValidUntil)
	if err != nil {
		return time.Time{}, err
	}
	until := identity.Earlier(i.ValidUntil, recovery.FreshUntil)
	for _, deadline := range []time.Time{current.ValidUntil, current.VerifiedIdentity.ValidUntil, f.eligibility.ValidUntil, f.eligibility.VerifiedIdentity.ValidUntil, f.target.FreshUntil, f.capability.FreshUntil, f.retention.ValidUntil, f.storage.Binding.FreshUntil} {
		until = identity.Earlier(until, deadline)
	}
	if ctx.Err() != nil || !s.Now().Before(until) {
		return time.Time{}, value.ErrUnavailable
	}
	return until, nil
}
