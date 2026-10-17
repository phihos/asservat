package identity

import (
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"time"
)

// CredentialSchedulePolicy refreshes scheduling observations only. The window
// originated in one verified credential resolution; it carries no groups or
// token and cannot authorize a refresh claim, identity or evidence disclosure.
type CredentialSchedulePolicy interface {
	ShortenCredentialWindow(context.Context, value.Principal, CredentialWindow) (CredentialWindow, error)
}

// ShortenCredentialWindow reuses the protected policy reader without decoding,
// decrypting or refreshing a provider credential. A changed policy can only
// shorten the original token/group bounds. New credentials need a new verified
// resolution. Every eventual claim still evaluates current identity in full.
func (s Service) ShortenCredentialWindow(ctx context.Context, principal value.Principal, previous CredentialWindow) (CredentialWindow, error) {
	var zero CredentialWindow
	if ctx == nil || ctx.Err() != nil || s.Policies == nil || s.Now == nil || !principal.Valid() {
		return zero, value.ErrUnavailable
	}
	start := s.Now()
	// Its old five-second observation is deliberately allowed to have expired;
	// only immutable verified dates are reused, never old eligibility facts.
	if !previous.Policy.Valid() || previous.IssuedAt.IsZero() || previous.IssuedAt.After(start) || !previous.TokenExpiresAt.After(previous.IssuedAt) || !previous.GroupsExpireAt.After(previous.IssuedAt) || previous.GroupsExpireAt.After(previous.IssuedAt.Add(5*time.Minute)) || !start.Before(previous.TokenExpiresAt) || !start.Before(previous.GroupsExpireAt) {
		return zero, value.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	policy, e := s.Policies.IdentityPolicy(ctx, principal.Issuer)
	if e != nil || ctx.Err() != nil || policy.Issuer != principal.Issuer || policy.Validate(s.Now()) != nil {
		return zero, value.ErrUnavailable
	}
	allowedClient := false
	for _, client := range policy.Clients {
		if client.ID == principal.ClientID && client.Kind == principal.Kind && client.ClassQualified {
			allowedClient = true
		}
	}
	if !allowedClient {
		return zero, value.ErrDenied
	}
	next := previous
	next.GroupsExpireAt = value.Earlier(previous.GroupsExpireAt, previous.IssuedAt.Add(policy.GroupMaxAge))
	next.Policy = policy.Revision
	next.ObservedAt = start
	next.FreshUntil = value.Earlier(start.Add(5*time.Second), policy.FreshUntil)
	if !next.Valid(s.Now()) || ctx.Err() != nil {
		return zero, value.ErrDenied
	}
	return next, nil
}
