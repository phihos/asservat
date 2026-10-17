// Package identity resolves credentials against current organization policy.
package identity

import (
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"time"
)

type TokenVerifier interface {
	Verify(context.Context, string) (value.Claims, error)
}
type PolicyReader interface {
	IdentityPolicy(context.Context, string) (value.Policy, error)
}
type Resolver interface {
	Resolve(context.Context, string) (value.Identity, error)
}
type Service struct {
	Tokens   TokenVerifier
	Policies PolicyReader
	Now      func() time.Time
}

// There is intentionally no permissive/static production PolicyReader. The
// accepted Kubernetes projection must provide current revocation/freshness.
func (s Service) Resolve(ctx context.Context, token string) (value.Identity, error) {
	v, err := s.ObserveCredential(ctx, token)
	return v.Identity, err
}

// ObserveCredential verifies once and evaluates one current policy. Its private
// scheduling window is independent of the short identity observation.
func (s Service) ObserveCredential(ctx context.Context, token string) (CredentialObservation, error) {
	var zero CredentialObservation
	if s.Tokens == nil || s.Policies == nil || s.Now == nil {
		return zero, value.ErrUnavailable
	}
	if ctx == nil {
		return zero, value.ErrUnavailable
	}
	started := s.Now()
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	claims, err := s.Tokens.Verify(ctx, token)
	if err != nil {
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		if errors.Is(err, value.ErrInvalid) {
			return zero, value.ErrInvalid
		}
		if errors.Is(err, value.ErrDenied) {
			return zero, value.ErrDenied
		}
		return zero, value.ErrUnavailable
	}
	p, err := s.Policies.IdentityPolicy(ctx, claims.Issuer)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	i, err := value.Admit(claims, p, s.Now())
	if err != nil {
		return zero, err
	}
	w := CredentialWindow{IssuedAt: claims.IssuedAt, TokenExpiresAt: claims.ExpiresAt, GroupsExpireAt: claims.IssuedAt.Add(p.GroupMaxAge), Policy: p.Revision, ObservedAt: started, FreshUntil: value.Earlier(started.Add(5*time.Second), i.ValidUntil)}
	if !w.Valid(s.Now()) || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	return CredentialObservation{Identity: i, Window: w}, nil
}
