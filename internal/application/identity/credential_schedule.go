package identity

import (
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"time"
)

// CredentialWindow schedules token work; it never grants identity or evidence
// authority. The protected policy and verified token supplied all of its dates.
type CredentialWindow struct {
	IssuedAt, TokenExpiresAt, GroupsExpireAt time.Time
	Policy                                   value.Revision
	ObservedAt, FreshUntil                   time.Time
}

func (w CredentialWindow) Valid(now time.Time) bool {
	return w.Policy.Valid() && !w.IssuedAt.IsZero() && !w.IssuedAt.After(now) && w.TokenExpiresAt.After(w.IssuedAt) && w.GroupsExpireAt.After(w.IssuedAt) && !w.GroupsExpireAt.After(w.IssuedAt.Add(5*time.Minute)) && now.Before(w.TokenExpiresAt) && now.Before(w.GroupsExpireAt) && value.Fresh(w.ObservedAt, w.FreshUntil, now, 5*time.Second)
}

// RefreshAt is deterministic for this credential/policy. A short authorization
// observation is deliberately not a token deadline. Callers only shorten an
// already scheduled time for the same credential version.
func (w CredentialWindow) RefreshAt(end time.Time) time.Time {
	due := value.Earlier(w.IssuedAt.Add(time.Minute), end)
	for _, deadline := range []time.Time{w.TokenExpiresAt, w.GroupsExpireAt} {
		lead := deadline.Sub(w.IssuedAt) / 2
		if lead > 15*time.Second {
			lead = 15 * time.Second
		}
		due = value.Earlier(due, deadline.Add(-lead))
	}
	return due
}

type CredentialObservation struct {
	Identity value.Identity
	Window   CredentialWindow
}
type CredentialObserver interface {
	ObserveCredential(context.Context, string) (CredentialObservation, error)
}

func resolveBrowserCredential(ctx context.Context, resolver Resolver, token string, now func() time.Time) (value.Identity, CredentialWindow, error) {
	if source, ok := resolver.(CredentialObserver); ok {
		v, err := source.ObserveCredential(ctx, token)
		if err != nil {
			return value.Identity{}, CredentialWindow{}, err
		}
		if ctx.Err() != nil || !v.Identity.Valid(now()) || !v.Window.Valid(now()) || v.Window.Policy != v.Identity.Policy || v.Window.FreshUntil.After(v.Identity.ValidUntil) {
			return value.Identity{}, CredentialWindow{}, value.ErrUnavailable
		}
		v.Identity.ValidUntil = value.Earlier(v.Identity.ValidUntil, v.Window.FreshUntil)
		return v.Identity, v.Window, nil
	}
	// Existing component resolvers remain compatible. A long-running refresh
	// owner requires CredentialObserver and cannot use this legacy fallback.
	i, err := resolver.Resolve(ctx, token)
	return i, CredentialWindow{}, err
}
func credentialRefreshAt(now, tokenEnd, sessionEnd time.Time, w CredentialWindow) time.Time {
	due := refreshTime(now, tokenEnd, sessionEnd)
	if w.Valid(now) {
		due = value.Earlier(due, w.RefreshAt(sessionEnd))
	}
	// Login may finish after the proactive point while this token remains
	// valid. The session stores an immediate future schedule, not a past date.
	if !due.After(now) {
		due = now.Add(time.Microsecond)
	}
	return due
}
