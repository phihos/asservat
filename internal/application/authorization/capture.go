package authorization

import (
	"context"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextEligibility obtains one current identity/permission observation for
// both caller eligibility and complete default audience. It performs no capture,
// artifact lookup, share materialization, audit or publication.
func (s Evaluator) ContextEligibility(ctx context.Context, token string, target value.Target) value.CaptureEligibility {
	return s.ContextEligibilityCurrent(ctx, credentialIdentity{s.Identities, token}, target)
}

func (s Evaluator) ContextEligibilityCurrent(ctx context.Context, current identities.CurrentIdentity, target value.Target) value.CaptureEligibility {
	deny := func(reason string) value.CaptureEligibility {
		return value.CaptureEligibility{Result: value.Result{Reason: reason}}
	}
	if current == nil || s.Permissions == nil || s.Now == nil || ctx.Err() != nil {
		return deny("AuthorityUnavailable")
	}
	if !target.Valid() {
		return deny("InvalidRequest")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return deny("IdentityUnavailable")
	}
	p, err := s.Permissions.Permissions(ctx, target)
	if err != nil {
		return deny("PermissionUnavailable")
	}
	fresh, err := current.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy || ctx.Err() != nil {
		return deny("AuthorityUnavailable")
	}
	fresh.ValidUntil = identity.Earlier(fresh.ValidUntil, i.ValidUntil)
	return value.ContextEligibility(fresh, p, target, s.Now())
}
