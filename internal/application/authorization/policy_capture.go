package authorization

import (
	"context"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// CaptureEligibility is the context-collection eligibility port shared by
// the investigation and the hub-run regional start. A human request keeps
// the ordinary evaluator. An accepted policy's executor (ADR-228) is
// evaluated through its current acceptance and team delegation: it has no
// scopes or groups, and the default audience is computed exactly as for a
// human, so neither the creator nor the executor joins it.
type CaptureEligibility struct {
	Human    Evaluator
	Accepted AcceptedPolicyReader
	Current  AutomationAuthorityReader
	Now      func() time.Time
}

func (s CaptureEligibility) ContextEligibilityCurrent(ctx context.Context, current identities.CurrentIdentity, target value.Target) value.CaptureEligibility {
	deny := func(reason string) value.CaptureEligibility {
		return value.CaptureEligibility{Result: value.Result{Reason: reason}}
	}
	if current == nil || s.Now == nil || ctx == nil || ctx.Err() != nil {
		return deny("AuthorityUnavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return deny("IdentityUnavailable")
	}
	_, policy, ok := value.PolicyExecutor(i.Principal)
	if !ok {
		return s.Human.ContextEligibilityCurrent(ctx, current, target)
	}
	if s.Accepted == nil || s.Current == nil {
		return deny("AutomationUnavailable")
	}
	accepted, err := s.Accepted.AcceptedPolicyAuthority(ctx, policy)
	if err != nil || accepted.Authority.Executor != i.Principal {
		return deny("AutomationUnavailable")
	}
	p, err := s.Current.PolicyAutomationAuthority(ctx, accepted.Authority, target)
	if err != nil {
		return deny("AutomationUnavailable")
	}
	fresh, err := current.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy || ctx.Err() != nil {
		return deny("AuthorityUnavailable")
	}
	fresh.ValidUntil = identity.Earlier(fresh.ValidUntil, i.ValidUntil)
	out := value.PolicyContextEligibility(fresh, accepted.Authority, p, target, s.Now())
	if out.Eligible {
		// Recovery is checked by every effect transaction itself; the policy's
		// own bound is its source observation and expiry (ADR-228).
		out.ValidUntil = identity.Earlier(out.ValidUntil, accepted.SourceUntil)
		if !s.Now().Before(out.ValidUntil) {
			return deny("AutomationUnavailable")
		}
	}
	return out
}
