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
func TestBrowserLoginSchedulesRefreshBeforeShortGroupAge(t *testing.T) {
	now, old, browser, cookie := handoffFixture(t)
	f, verified := newFixture()
	f.now = *now
	f.c.Issuer = browser.Issuer
	f.c.Subject = old.record.Principal.Subject
	f.c.IssuedAt = *now
	f.c.ExpiresAt = now.Add(10 * time.Minute)
	f.c.KeyUntil = now.Add(5 * time.Second)
	f.p.Issuer = browser.Issuer
	f.p.ObservedAt = *now
	f.p.FreshUntil = now.Add(5 * time.Second)
	f.p.GroupMaxAge = 10 * time.Second
	store := &scheduleStore{handoffStore: old}
	browser.Store = store
	browser.Identities = verified
	p := browser.Provider.(handoffProvider)
	p.tokens.ExpiresAt = f.c.ExpiresAt
	browser.Provider = p
	if _, err := browser.Complete(context.Background(), cookie, cookie, "code"); err != nil {
		t.Fatal(err)
	}
	due := store.createdRecord.RefreshAt
	if !due.After(*now) || !due.Before(f.c.IssuedAt.Add(f.p.GroupMaxAge)) {
		t.Fatalf("refresh due %s does not precede group expiry %s", due, f.c.IssuedAt.Add(f.p.GroupMaxAge))
	}
	if due.Before(now.Add(time.Second)) {
		t.Fatal("short policy/key observation used as refresh schedule", due)
	}
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
	f.p.GroupMaxAge = 40 * time.Second
	f.p.FreshUntil = f.now.Add(2 * time.Second)
	observed, err := s.ObserveCredential(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if f.reads != 1 || verifier.calls != 1 {
		t.Fatal("credential resolution repeated verification/policy", verifier.calls, f.reads)
	}
	if !observed.Window.GroupsExpireAt.Equal(f.now.Add(40*time.Second)) || !observed.Identity.ValidUntil.Equal(f.p.FreshUntil) || !observed.Window.FreshUntil.Equal(f.p.FreshUntil) {
		t.Fatal("scheduling changed or renewed identity authority", observed)
	}
	if due := observed.Window.RefreshAt(f.now.Add(time.Hour)); !due.Equal(f.now.Add(25 * time.Second)) {
		t.Fatal("policy observation became token deadline", due)
	}
	if observed.Window.Valid(f.p.FreshUntil) {
		t.Fatal("expired policy still supplies current scheduling observation")
	}
	f.p.GroupMaxAge = 10 * time.Second
	shorter, err := s.ObserveCredential(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if due := shorter.Window.RefreshAt(f.now.Add(time.Hour)); !due.Equal(f.now.Add(5 * time.Second)) {
		t.Fatal("current stricter policy did not shorten schedule", due)
	}
}
func TestCredentialWindowDoesNotEscapeAfterBlockingPolicy(t *testing.T) {
	for _, kind := range []string{"expired-key", "expired-policy", "expired-group", "short-interval"} {
		t.Run(kind, func(t *testing.T) {
			f, s := newFixture()
			f.c.IssuedAt = f.now
			f.c.ExpiresAt = f.now.Add(time.Minute)
			f.c.KeyUntil = f.now.Add(time.Minute)
			f.p.FreshUntil = f.now.Add(time.Minute)
			f.advance = 6 * time.Second
			switch kind {
			case "expired-key":
				f.c.KeyUntil = f.now.Add(time.Second)
			case "expired-policy":
				f.p.FreshUntil = f.now.Add(time.Second)
			case "expired-group":
				f.p.GroupMaxAge = time.Second
			}
			if v, e := s.ObserveCredential(context.Background(), "token"); e == nil || v.Identity.Principal.Valid() || !v.Window.IssuedAt.IsZero() {
				t.Fatal("blocking work revived scheduling observation", e, v)
			}
		})
	}
}

func TestCredentialRefreshScheduleCanBeImmediatelyDueWithoutExtendingIdentity(t *testing.T) {
	f, s := newFixture()
	f.c.IssuedAt = f.now.Add(-8 * time.Second)
	f.p.GroupMaxAge = 10 * time.Second
	v, e := s.ObserveCredential(context.Background(), "token")
	if e != nil {
		t.Fatal(e)
	}
	due := credentialRefreshAt(f.now, f.c.ExpiresAt, f.now.Add(time.Hour), v.Window)
	if !due.After(f.now) || !due.Before(v.Window.GroupsExpireAt) {
		t.Fatal("past proactive point yielded invalid session schedule", due)
	}
	if !v.Identity.ValidUntil.Equal(v.Window.GroupsExpireAt) {
		t.Fatal("schedule extended short identity", v.Identity.ValidUntil)
	}
}
