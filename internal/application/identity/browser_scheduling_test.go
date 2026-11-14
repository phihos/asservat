package identity

import (
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
	"time"
)

type scheduleStore struct {
	*handoffStore
	createdRecord value.BrowserSession
}

func (s *scheduleStore) CreateSession(_ context.Context, r value.BrowserSession) (value.BrowserSession, error) {
	s.createdRecord = r
	r.Observation = s.record.Observation
	return r, nil
}

type countedScheduleVerifier struct {
	TokenVerifier
	calls int
}

func (v *countedScheduleVerifier) Verify(ctx context.Context, token string) (value.Claims, error) {
	v.calls++
	return v.TokenVerifier.Verify(ctx, token)
}
func TestCredentialWindowUsesOneVerificationAndKeepsPolicyDeadline(t *testing.T) {
	f, s := newFixture()
	verifier := &countedScheduleVerifier{TokenVerifier: s.Tokens}
	s.Tokens = verifier
	f.c.IssuedAt = f.now
	f.c.ExpiresAt = f.now.Add(time.Hour)
	f.p.FreshUntil = f.now.Add(2 * time.Second)
	observed, err := s.ObserveCredential(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if f.reads != 1 || verifier.calls != 1 {
		t.Fatal("credential resolution repeated verification/policy", verifier.calls, f.reads)
	}
	if !observed.Identity.ValidUntil.Equal(f.p.FreshUntil) || !observed.Window.FreshUntil.Equal(f.p.FreshUntil) {
		t.Fatal("scheduling changed or renewed identity authority", observed)
	}
	if due := observed.Window.RefreshAt(f.now.Add(time.Hour)); !due.Equal(f.now.Add(time.Minute)) {
		t.Fatal("policy observation became token deadline", due)
	}
	if observed.Window.Valid(f.p.FreshUntil) {
		t.Fatal("expired policy still supplies current scheduling observation")
	}
}
func TestCredentialWindowDoesNotEscapeAfterBlockingPolicy(t *testing.T) {
	for _, kind := range []string{"expired-key", "expired-policy", "short-interval"} {
		t.Run(kind, func(t *testing.T) {
			f, s := newFixture()
			f.c.IssuedAt = f.now
			f.c.ExpiresAt = f.now.Add(time.Minute)
			f.c.KeyUntil = f.now.Add(time.Minute)
			f.p.FreshUntil = f.now.Add(time.Minute)
			// ADR-311: the scheduling observation lasts one recheck interval.
			f.advance = value.AuthorityRecheckInterval + time.Second
			switch kind {
			case "expired-key":
				f.c.KeyUntil = f.now.Add(time.Second)
			case "expired-policy":
				f.p.FreshUntil = f.now.Add(time.Second)
			}
			if v, e := s.ObserveCredential(context.Background(), "token"); e == nil || v.Identity.Principal.Valid() || !v.Window.IssuedAt.IsZero() {
				t.Fatal("blocking work revived scheduling observation", e, v)
			}
		})
	}
}

func TestBrowserCredentialSchedulingWindowDoesNotShortenVerifiedIdentity(t *testing.T) {
	f, s := newFixture()
	f.c.KeyUntil = f.now.Add(time.Minute)
	observation, err := s.ObserveCredential(t.Context(), "synthetic-access")
	if err != nil || !observation.Identity.ValidUntil.Equal(f.now.Add(30*time.Second)) || !observation.Window.FreshUntil.Equal(f.now.Add(value.AuthorityRecheckInterval)) {
		t.Fatal("real verified policy and scheduling windows", err, observation)
	}
	identity, window, err := resolveBrowserCredential(t.Context(), s, "synthetic-access", s.Now)
	if err != nil || !identity.ValidUntil.Equal(observation.Identity.ValidUntil) || window != observation.Window {
		t.Fatal("token refresh scheduling shortened actual identity authority", err, identity.ValidUntil, observation.Identity.ValidUntil)
	}
}
