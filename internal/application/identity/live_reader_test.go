package identity

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

type liveClock struct{ at atomic.Int64 }

func newLiveClock() *liveClock {
	c := &liveClock{}
	c.at.Store(time.Now().UnixNano())
	return c
}
func (c *liveClock) now() time.Time      { return time.Unix(0, c.at.Load()) }
func (c *liveClock) add(d time.Duration) { c.at.Add(int64(d)) }

type liveSessions func(context.Context, string, bool) (SessionView, error)

func (s liveSessions) Resolve(ctx context.Context, cookie string, refresh bool) (SessionView, error) {
	return s(ctx, cookie, refresh)
}

func TestLiveReaderFreshBatchesDoNotRenewRetainedMetadataHandles(t *testing.T) {
	c := newLiveClock()
	principal := requestIdentity(c.now()).Principal
	expires := c.now().Add(time.Hour)
	groups := []string{"original-team"}
	var calls int
	sessions := liveSessions(func(_ context.Context, cookie string, refresh bool) (SessionView, error) {
		calls++
		if refresh || cookie != "original-cookie" {
			t.Fatal("GET refreshed or replaced its cookie")
		}
		i := requestIdentity(c.now())
		i.Groups = slices.Clone(groups)
		return SessionView{Identity: i, ExpiresAt: expires}, nil
	})
	r, err := NewBrowserLiveReader(t.Context(), sessions, "original-cookie", principal, expires, c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	first, err := r.BeginBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	initial, err := first.ResolveIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c.add(6 * time.Second)
	before := calls
	if _, err := first.ResolveIdentity(context.Background()); err == nil || calls != before {
		t.Fatal("expired batch reauthenticated")
	}
	if _, err := r.BeginBatch(t.Context()); !errors.Is(err, ErrReaderBusy) {
		t.Fatal("expired batch released without joining", err)
	}
	first.Close()
	groups = []string{"replacement-team"}
	second, err := r.BeginBatch(t.Context())
	if err != nil {
		t.Fatal("reader could not continue after five seconds", err)
	}
	defer second.Close()
	current, err := second.ResolveIdentity(t.Context())
	if err != nil || !slices.Equal(current.Groups, groups) || !current.ValidUntil.After(initial.ValidUntil) {
		t.Fatal("new batch replayed old groups or deadline", current, err)
	}
	before = calls
	if _, err := first.ResolveIdentity(context.Background()); err == nil || calls != before {
		t.Fatal("closed batch used retained credentials")
	}
	groups = []string{"changed-within-batch"}
	if _, err := second.ResolveIdentity(t.Context()); err == nil {
		t.Fatal("batch accepted changed current claims")
	}
}

func TestLiveReaderKeepsShorterSessionExpiryFromFailedBatch(t *testing.T) {
	c := newLiveClock()
	start := c.now()
	principal := requestIdentity(start).Principal
	var calls int
	sessions := liveSessions(func(_ context.Context, _ string, refresh bool) (SessionView, error) {
		if refresh {
			t.Fatal("implicit refresh")
		}
		calls++
		i := requestIdentity(c.now())
		expires := start.Add(time.Hour)
		if calls == 2 {
			expires = start.Add(30 * time.Second)
			c.add(6 * time.Second) // Source remains valid; original batch interval expired.
		}
		return SessionView{Identity: i, ExpiresAt: expires}, nil
	})
	r, err := NewBrowserLiveReader(t.Context(), sessions, "cookie", principal, start.Add(time.Hour), c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.BeginBatch(t.Context()); err == nil {
		t.Fatal("slow batch was renewed")
	}
	c.add(25 * time.Second)
	if _, err := r.BeginBatch(t.Context()); err == nil || calls != 2 {
		t.Fatal("failed batch discarded known shorter session bound", err, calls)
	}
}

func TestLiveReaderShortenedObservationExpiryDoesNotTerminateGET(t *testing.T) {
	c := newLiveClock()
	start := c.now()
	calls := 0
	resolver := requestResolver(func(context.Context, string) (value.Identity, error) {
		calls++
		i := requestIdentity(c.now())
		if calls == 3 {
			i.ValidUntil = start.Add(2 * time.Second)
		}
		return i, nil
	})
	r, err := NewBearerLiveReader(t.Context(), resolver, "token", requestIdentity(start).Principal, start.Add(time.Hour), c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	first, err := r.BeginBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	shorter, err := first.ResolveIdentity(t.Context())
	if err != nil || !shorter.ValidUntil.Equal(start.Add(2*time.Second)) {
		t.Fatal("shortening not observed", err)
	}
	c.add(3 * time.Second)
	if _, err = first.ResolveIdentity(t.Context()); !errors.Is(err, value.ErrDenied) || calls != 3 {
		t.Fatal("expired observation used source", err, calls)
	}
	first.Close()
	next, err := r.BeginBatch(t.Context())
	if err != nil {
		t.Fatal("observation expiry incorrectly terminated GET", err)
	}
	next.Close()
}

func TestLiveReaderTypedBusyDoesNotRefreshOrRetry(t *testing.T) {
	c := newLiveClock()
	var busy bool
	var calls int
	sessions := liveSessions(func(_ context.Context, _ string, refresh bool) (SessionView, error) {
		calls++
		if refresh {
			t.Fatal("implicit refresh")
		}
		if busy {
			return SessionView{}, value.ErrSessionBusy
		}
		return SessionView{Identity: requestIdentity(c.now()), ExpiresAt: c.now().Add(time.Hour)}, nil
	})
	r, err := NewBrowserLiveReader(t.Context(), sessions, "cookie", requestIdentity(c.now()).Principal, c.now().Add(time.Hour), c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	busy = true
	before := calls
	if _, err := r.BeginBatch(t.Context()); !errors.Is(err, value.ErrSessionBusy) || calls != before+1 {
		t.Fatal("refresh busy lost type or retried", err, calls)
	}
	busy = false // An independently completed POST, not action by this reader.
	b, err := r.BeginBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
}

func TestLiveReaderPinsActorClientAndOriginalHardDeadline(t *testing.T) {
	for _, mode := range []string{"subject", "client", "hard-end", "revoked", "settings-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			c := newLiveClock()
			principal := requestIdentity(c.now()).Principal
			until := c.now().Add(20 * time.Second)
			calls := 0
			changed := false
			sessions := liveSessions(func(context.Context, string, bool) (SessionView, error) {
				calls++
				i := requestIdentity(c.now())
				if changed {
					switch mode {
					case "subject":
						i.Principal.Subject = "someone-else"
					case "client":
						i.Principal.ClientID = "other-client"
					case "revoked":
						return SessionView{}, value.ErrDenied
					case "settings-unavailable":
						return SessionView{}, value.ErrUnavailable
					}
				}
				return SessionView{Identity: i, ExpiresAt: until.Add(time.Hour)}, nil
			})
			r, err := NewBrowserLiveReader(t.Context(), sessions, "cookie", principal, until, c.now)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			changed = true
			if mode == "hard-end" {
				c.add(20 * time.Second)
			}
			_, err = r.BeginBatch(t.Context())
			if err == nil {
				t.Fatal("changed or expired reader accepted")
			}
			if mode == "hard-end" && calls != 1 {
				t.Fatal("expired reader invoked provider")
			}
			if mode == "settings-unavailable" && !errors.Is(err, value.ErrUnavailable) {
				t.Fatal("provider error type lost", err)
			}
		})
	}
}

func TestLiveReaderBearerDoesNotRenewTokenOrGroupAge(t *testing.T) {
	for _, cause := range []string{"token-expiry", "group-age"} {
		t.Run(cause, func(t *testing.T) {
			c := newLiveClock()
			start := c.now()
			calls := 0
			resolver := requestResolver(func(_ context.Context, token string) (value.Identity, error) {
				calls++
				if token != "original-token" {
					t.Fatal("bearer fabricated or substituted")
				}
				i := requestIdentity(c.now())
				p := value.Policy{Revision: i.Policy, Issuer: i.Principal.Issuer, ObservedAt: c.now(), FreshUntil: c.now().Add(time.Minute), Clients: []value.Client{{ID: i.Principal.ClientID, Kind: value.Human, ClassQualified: true}}, EligibleSubjects: []value.Subject{{ID: i.Principal.Subject, Kind: value.Human}}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute}
				claims := value.Claims{Issuer: i.Principal.Issuer, Subject: i.Principal.Subject, ClientID: i.Principal.ClientID, Scopes: i.Scopes, Groups: i.Groups, IssuedAt: start, ExpiresAt: start.Add(time.Minute), KeyUntil: start.Add(time.Hour)}
				if cause == "token-expiry" {
					claims.ExpiresAt = start.Add(10 * time.Second)
				} else {
					p.GroupMaxAge = 10 * time.Second
				}
				return value.Admit(claims, p, c.now())
			})
			r, err := NewBearerLiveReader(t.Context(), resolver, "original-token", requestIdentity(start).Principal, start.Add(time.Hour), c.now)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			c.add(6 * time.Second)
			b, err := r.BeginBatch(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			b.Close()
			c.add(5 * time.Second)
			if _, err = r.BeginBatch(t.Context()); !errors.Is(err, value.ErrDenied) || calls != 3 {
				t.Fatal("old credential age renewed", err, calls)
			}
		})
	}
}

func TestLiveBatchCloseJoinsBlockedObservationBeforeFreeingSlot(t *testing.T) {
	c := newLiveClock()
	var calls atomic.Int64
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	resolver := requestResolver(func(ctx context.Context, _ string) (value.Identity, error) {
		if calls.Add(1) == 3 {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			<-release
		}
		return requestIdentity(c.now()), nil
	})
	r, err := NewBearerLiveReader(t.Context(), resolver, "token", requestIdentity(c.now()).Principal, c.now().Add(time.Hour), c.now)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := r.BeginBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	resolved := make(chan error, 1)
	go func() { _, e := b.ResolveIdentity(context.Background()); resolved <- e }()
	<-entered
	closed := make(chan struct{})
	go func() { b.Close(); close(closed) }()
	<-cancelled
	select {
	case <-closed:
		t.Fatal("close returned before observer joined")
	default:
	}
	if _, err = r.BeginBatch(context.Background()); !errors.Is(err, ErrReaderBusy) {
		t.Fatal("blocked observer no longer counted", err)
	}
	if _, err = b.ResolveIdentity(context.Background()); err == nil || calls.Load() != 3 {
		t.Fatal("retained batch survived close")
	}
	close(release)
	if err = <-resolved; err == nil {
		t.Fatal("cancelled observer returned authority")
	}
	<-closed
	next, err := r.BeginBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

func TestLiveReaderCancellationJoinsInitializationAndCurrentRead(t *testing.T) {
	for _, during := range []string{"initializing-batch", "current-read"} {
		t.Run(during, func(t *testing.T) {
			c := newLiveClock()
			owner, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls atomic.Int64
			entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			blockAt := int64(2)
			if during == "current-read" {
				blockAt = 3
			}
			resolver := requestResolver(func(ctx context.Context, _ string) (value.Identity, error) {
				if calls.Add(1) == blockAt {
					close(entered)
					<-ctx.Done()
					close(cancelled)
					<-release
				}
				return requestIdentity(c.now()), nil
			})
			r, err := NewBearerLiveReader(owner, resolver, "token", requestIdentity(c.now()).Principal, c.now().Add(time.Hour), c.now)
			if err != nil {
				t.Fatal(err)
			}
			var b IdentityBatch
			if during == "current-read" {
				b, err = r.BeginBatch(t.Context())
				if err != nil {
					t.Fatal(err)
				}
			}
			result := make(chan error, 1)
			go func() {
				if b != nil {
					_, e := b.ResolveIdentity(context.Background())
					result <- e
				} else {
					_, e := r.BeginBatch(context.Background())
					result <- e
				}
			}()
			<-entered
			cancel()
			<-cancelled
			closed := make(chan struct{})
			go func() { r.Close(); close(closed) }()
			select {
			case <-closed:
				t.Fatal("reader close returned before cancelled observer joined")
			default:
			}
			close(release)
			if err = <-result; err == nil {
				t.Fatal("Background detached original cancellation")
			}
			<-closed
			if _, err = r.BeginBatch(context.Background()); err == nil || calls.Load() != blockAt {
				t.Fatal("closed reader restarted")
			}
		})
	}
}
