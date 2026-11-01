package identity

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

func TestCurrentRequestNeverReextendsAShortenedObservation(t *testing.T) {
	now := time.Now()
	var calls atomic.Int64
	resolver := requestResolver(func(context.Context, string) (value.Identity, error) {
		i := requestIdentity(now)
		if calls.Add(1) == 2 {
			i.ValidUntil = now.Add(time.Second)
		}
		return i, nil
	})
	h, _, err := NewBearerRequest(t.Context(), resolver, "synthetic", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	shorter, err := h.ResolveIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	later, err := h.ResolveIdentity(t.Context())
	if err != nil || !later.ValidUntil.Equal(shorter.ValidUntil) {
		t.Fatalf("shortened identity renewed: %v %v", later.ValidUntil, err)
	}
	now = shorter.ValidUntil
	if _, err = h.ResolveIdentity(t.Context()); err == nil || calls.Load() != 3 {
		t.Fatal("expired shortened request invoked provider", err, calls.Load())
	}
}

func TestConcurrentIdentityReadKeepsOtherReadsShorterDeadline(t *testing.T) {
	now := time.Now()
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	resolver := requestResolver(func(context.Context, string) (value.Identity, error) {
		i := requestIdentity(now)
		switch calls.Add(1) {
		case 2:
			close(entered)
			<-release
		case 3:
			i.ValidUntil = now.Add(time.Second)
		}
		return i, nil
	})
	h, _, err := NewBearerRequest(t.Context(), resolver, "synthetic", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		i   value.Identity
		err error
	}
	done := make(chan result, 1)
	go func() { i, e := h.ResolveIdentity(t.Context()); done <- result{i, e} }()
	<-entered
	shorter, err := h.ResolveIdentity(t.Context())
	close(release)
	later := <-done
	if err != nil || later.err != nil || !later.i.ValidUntil.Equal(shorter.ValidUntil) {
		t.Fatalf("concurrent identity read restored old deadline: %v %v %v", later.i.ValidUntil, err, later.err)
	}
}

type requestResolver func(context.Context, string) (value.Identity, error)

func (r requestResolver) Resolve(ctx context.Context, token string) (value.Identity, error) {
	return r(ctx, token)
}

func requestIdentity(now time.Time) value.Identity {
	return value.Identity{Principal: value.Principal{Issuer: "https://issuer.invalid", Subject: "developer", ClientID: "console", Kind: value.Human}, Scopes: []string{"evidence:read", "evidence:capture"}, Groups: []string{"team-a", "team-b"}, Policy: value.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(time.Minute)}
}

func TestCurrentRequestRechecksClaimsWithoutExtendingItsOriginalInterval(t *testing.T) {
	for _, mode := range []string{"current", "reordered", "subject", "client", "policy", "groups", "scopes", "revoked", "blocked-expiry", "clock-reversal", "original-shorter"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
			i := requestIdentity(now)
			if mode == "original-shorter" {
				i.ValidUntil = now.Add(time.Second)
			}
			calls := 0
			resolver := requestResolver(func(_ context.Context, token string) (value.Identity, error) {
				calls++
				if token != "synthetic-request-token" {
					t.Fatal("credential substituted")
				}
				v := cloneIdentity(i)
				if calls > 1 {
					v.ValidUntil = now.Add(time.Minute)
					switch mode {
					case "reordered":
						v.Groups[0], v.Groups[1] = v.Groups[1], v.Groups[0]
					case "subject":
						v.Principal.Subject = "replacement"
					case "client":
						v.Principal.ClientID = "replacement"
					case "policy":
						v.Policy.Generation++
					case "groups":
						v.Groups = v.Groups[:1]
					case "scopes":
						v.Scopes = v.Scopes[:1]
					case "revoked":
						return value.Identity{}, value.ErrDenied
					case "blocked-expiry":
						now = now.Add(6 * time.Second)
					case "clock-reversal":
						now = now.Add(-time.Second)
					}
				}
				return v, nil
			})
			h, initial, err := NewBearerRequest(context.Background(), resolver, "synthetic-request-token", func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			until := initial.ValidUntil
			// Presentation code cannot mutate the private principal observation.
			initial.Groups[0] = "changed-display"
			v, err := h.ResolveIdentity(context.Background())
			allowed := mode == "current" || mode == "reordered" || mode == "original-shorter"
			if allowed {
				if err != nil || !v.ValidUntil.Equal(until) || calls != 2 {
					t.Fatal("current observation was not bounded by original authority", v, err, calls)
				}
				v.Groups[0] = "changed-result"
				if _, err = h.ResolveIdentity(context.Background()); err != nil {
					t.Fatal("result alias changed request state", err)
				}
			} else if err == nil {
				t.Fatal("changed or expired identity accepted")
			}
		})
	}
}

func TestCurrentRequestCannotDetachOriginalCancellation(t *testing.T) {
	for _, during := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-read", true: "during-read"}[during], func(t *testing.T) {
			now := time.Now()
			owner, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			calls := 0
			resolver := requestResolver(func(ctx context.Context, _ string) (value.Identity, error) {
				calls++
				if calls > 1 {
					close(entered)
					<-ctx.Done()
					// A misbehaving dependency returning success after cancellation
					// must not revive the original request.
				}
				return requestIdentity(now), nil
			})
			h, _, err := NewBearerRequest(owner, resolver, "synthetic", time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if !during {
				cancel()
				if _, err = h.ResolveIdentity(context.Background()); err == nil || calls != 1 {
					t.Fatal("cancelled owner invoked authority source")
				}
				return
			}
			done := make(chan error, 1)
			go func() { _, e := h.ResolveIdentity(context.Background()); done <- e }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("current observation did not begin")
			}
			cancel()
			select {
			case err = <-done:
				if err == nil {
					t.Fatal("background context detached original request")
				}
			case <-time.After(time.Second):
				t.Fatal("original cancellation did not interrupt current source")
			}
		})
	}
}

func TestBrowserCurrentRequestRechecksPersistedSessionAfterBlockingReads(t *testing.T) {
	for _, mode := range []string{"current", "revoked", "missing", "expired-after-read", "settings-renewal"} {
		t.Run(mode, func(t *testing.T) {
			now, store, service, cookie := handoffFixture(t)
			h, initial, err := NewBrowserRequest(context.Background(), service, cookie, false, service.Now)
			if err != nil {
				t.Fatal(err)
			}
			store.onRead = func(n int) {
				if n != 4 { // final SQL observation of the second session resolve
					return
				}
				switch mode {
				case "revoked":
					store.readErr = value.ErrDenied
				case "missing":
					store.record = value.BrowserSession{}
				case "expired-after-read":
					*now = now.Add(3 * time.Second)
				case "settings-renewal":
					store.record.Observation.ObservedAt = now.Add(time.Second)
					store.record.Observation.FreshUntil = now.Add(2 * time.Second)
					*now = now.Add(time.Second)
				}
			}
			v, err := h.ResolveIdentity(context.Background())
			if mode == "current" || mode == "settings-renewal" {
				if err != nil || v.ValidUntil.After(initial.Identity.ValidUntil) {
					t.Fatal("valid session handoff renewed original deadline", v, err)
				}
			} else if err == nil {
				t.Fatal("no-longer-current session authorized request")
			}
		})
	}
}

type refreshSession struct {
	i         value.Identity
	refreshes []bool
}

func (s *refreshSession) Resolve(_ context.Context, _ string, refresh bool) (SessionView, error) {
	s.refreshes = append(s.refreshes, refresh)
	return SessionView{Identity: s.i, ExpiresAt: s.i.ValidUntil.Add(time.Hour)}, nil
}

func TestBrowserCurrentRequestRefreshesOnlyAtIngress(t *testing.T) {
	now := time.Now()
	s := &refreshSession{i: requestIdentity(now)}
	h, _, err := NewBrowserRequest(context.Background(), s, "synthetic-cookie", true, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.ResolveIdentity(context.Background()); err != nil || len(s.refreshes) != 2 || !s.refreshes[0] || s.refreshes[1] {
		t.Fatal("current checks refreshed a credential", err, s.refreshes)
	}
	if _, _, err = NewBearerRequest(nil, nil, "", nil); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("invalid source accepted")
	}
}

func TestBrowserRequestWithinMatchesEvidenceReadWindow(t *testing.T) {
	now := time.Now()
	i := requestIdentity(now)
	i.ValidUntil = now.Add(time.Hour)
	s := &refreshSession{i: i}
	clock := func() time.Time { return now }
	_, v, err := NewBrowserRequestWithin(context.Background(), s, "synthetic-cookie", false, clock, value.EvidenceReadRequestWindow)
	if err != nil || !v.Identity.ValidUntil.Equal(now.Add(value.EvidenceReadRequestWindow)) {
		t.Fatal("browser evidence read not bounded by its window", err, v.Identity.ValidUntil.Sub(now))
	}
	_, v, err = NewBrowserRequest(context.Background(), s, "synthetic-cookie", false, clock)
	if err != nil || !v.Identity.ValidUntil.Equal(now.Add(5*time.Second)) {
		t.Fatal("ordinary browser request not five seconds", err)
	}
	if _, _, err = NewBrowserRequestWithin(context.Background(), s, "synthetic-cookie", false, clock, value.EvidenceReadRequestWindow+time.Second); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("browser window beyond the evidence-read maximum accepted")
	}
}

func TestRecordingSaveRequestWindowPreservesInitialIdentityAndOwner(t *testing.T) {
	for _, mode := range []string{"prospective", "initial-shorter", "later-shorter", "owner-cancelled"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			original := now
			calls := 0
			owner, cancel := context.WithCancel(t.Context())
			defer cancel()
			resolver := requestResolver(func(ctx context.Context, _ string) (value.Identity, error) {
				calls++
				i := requestIdentity(now)
				i.ValidUntil = original.Add(time.Minute)
				if mode == "initial-shorter" || mode == "later-shorter" && calls > 1 {
					i.ValidUntil = original.Add(4 * time.Second)
				}
				return i, ctx.Err()
			})
			current, initial, err := NewBearerRequestWithin(owner, resolver, "synthetic", func() time.Time { return now }, value.RecordingSaveRequestWindow)
			if err != nil {
				t.Fatal(err)
			}
			want := original.Add(value.RecordingSaveRequestWindow)
			if mode == "initial-shorter" {
				want = original.Add(4 * time.Second)
			}
			if !initial.ValidUntil.Equal(want) {
				t.Fatal("initial identity widened", initial.ValidUntil, want)
			}
			if mode == "later-shorter" {
				if _, err = current.ResolveIdentity(owner); err != nil {
					t.Fatal(err)
				}
				want = original.Add(4 * time.Second)
			}
			if mode == "owner-cancelled" {
				cancel()
			} else {
				now = want
			}
			before := calls
			if _, err = current.ResolveIdentity(context.Background()); err == nil || calls != before {
				t.Fatal("expired/cancelled original request consulted provider or renewed", err, calls, before)
			}
		})
	}
}
