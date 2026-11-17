package identity

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

// Recorded is a requester as recorded with an approval request (ADR-335 D5):
// the principal with its verified groups, scopes and identity policy
// revision. It resolves only before until, the recorded end of the
// requester's authentication, so recorded groups never outlive it.
func Recorded(principal value.Principal, groups, scopes []string, policy value.Revision, until time.Time, now func() time.Time) CurrentIdentity {
	return recorded{value.Identity{Principal: principal, Groups: groups, Scopes: scopes, Policy: policy, AuthenticatedUntil: until}, now}
}

type recorded struct {
	i   value.Identity
	now func() time.Time
}

func (r recorded) ResolveIdentity(ctx context.Context) (value.Identity, error) {
	n := r.now()
	if ctx == nil || ctx.Err() != nil || !n.Before(r.i.AuthenticatedUntil) {
		return value.Identity{}, value.ErrDenied
	}
	i := cloneIdentity(r.i)
	i.VerifiedAt, i.ValidUntil = n, value.Earlier(r.i.AuthenticatedUntil, n.Add(value.AuthorityRecheckInterval))
	if !i.Valid(n) {
		return value.Identity{}, value.ErrDenied
	}
	return i, nil
}
