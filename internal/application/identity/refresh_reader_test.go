package identity

import (
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type pauseReaderFunc func(context.Context, [32]byte, value.Principal, value.RefreshResponseBinding) (value.RefreshPause, error)

func (f pauseReaderFunc) BrowserRefreshPause(c context.Context, k [32]byte, p value.Principal, b value.RefreshResponseBinding) (value.RefreshPause, error) {
	return f(c, k, p, b)
}
func refreshUUID() string { return "11111111-1111-4111-8111-111111111111" }
func pauseFixture(t *testing.T, reader BrowserRefreshPauseReader) (*BrowserRefreshReader, *liveClock, value.RefreshResponseBinding) {
	t.Helper()
	c := newLiveClock()
	i := requestIdentity(c.now())
	cookie := randomSessionSecret()
	sessions := liveSessions(func(_ context.Context, got string, refresh bool) (SessionView, error) {
		if refresh || got != cookie {
			t.Fatal("pause identity refreshed or substituted credential")
		}
		return SessionView{Identity: requestIdentity(c.now()), ExpiresAt: c.now().Add(time.Hour)}, nil
	})
	r, e := NewBrowserRefreshReader(t.Context(), sessions, reader, cookie, i.Principal, c.now().Add(time.Minute), c.now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(r.Close)
	return r, c, value.RefreshResponseBinding{DownloadID: refreshUUID(), ResponseID: refreshUUID(), ResponseOwnerID: refreshUUID(), ResponseGeneration: 1}
}
func pauseValue(c *liveClock, key [32]byte, b value.RefreshResponseBinding) value.RefreshPause {
	return value.RefreshPause{Owner: value.RefreshOwnerRef{RootID: refreshUUID(), Epoch: refreshUUID(), OwnerID: refreshUUID(), InstallationID: refreshUUID(), ClusterID: refreshUUID(), PodUID: refreshUUID(), ProcessEpoch: refreshUUID(), SessionID: key, Generation: 1}, DownloadID: b.DownloadID, ResponseID: b.ResponseID, ResponseOwnerID: b.ResponseOwnerID, ResponseGeneration: b.ResponseGeneration, CredentialVersion: 1, ObservedAt: c.now(), ValidUntil: c.now().Add(5 * time.Second), ClaimUntil: c.now().Add(10 * time.Second)}
}
func TestOwnedRefreshPausePreservesBoundAndRejectsSubstitution(t *testing.T) {
	for _, kind := range []string{"valid", "settled", "foreign-session", "foreign-response", "expired-original", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			var clock *liveClock
			r, c, b := pauseFixture(t, pauseReaderFunc(func(ctx context.Context, key [32]byte, p value.Principal, b value.RefreshResponseBinding) (value.RefreshPause, error) {
				v := pauseValue(clock, key, b)
				switch kind {
				case "settled":
					v.Settled = true
				case "foreign-session":
					v.Owner.SessionID[0]++
				case "foreign-response":
					v.ResponseGeneration++
				case "expired-original":
					clock.add(6 * time.Second)
				}
				return v, nil
			}))
			clock = c
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			v, e := r.OwnedRefreshPause(ctx, b)
			if kind == "valid" || kind == "settled" {
				if e != nil || !v.Valid(c.now()) || v.Settled != (kind == "settled") {
					t.Fatal(v, e)
				}
			} else if e == nil {
				t.Fatal("invalid pause escaped", v)
			}
		})
	}
}
func TestOwnedRefreshPauseCloseJoinsBlockedLookupAndOriginalCancellation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var clock *liveClock
	r, c, b := pauseFixture(t, pauseReaderFunc(func(ctx context.Context, key [32]byte, p value.Principal, b value.RefreshResponseBinding) (value.RefreshPause, error) {
		calls.Add(1)
		close(entered)
		<-release
		return pauseValue(clock, key, b), nil
	}))
	clock = c
	result := make(chan error, 1)
	go func() { _, e := r.OwnedRefreshPause(context.Background(), b); result <- e }()
	<-entered
	if _, e := r.BeginBatch(context.Background()); !errors.Is(e, ErrReaderBusy) {
		t.Fatal("blocked lookup escaped one-batch accounting", e)
	}
	closed := make(chan struct{})
	go func() { r.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close did not join protected lookup")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if e := <-result; e == nil {
		t.Fatal("Background detached original reader cancellation")
	}
	<-closed
	if _, e := r.OwnedRefreshPause(context.Background(), b); e == nil || calls.Load() != 1 {
		t.Fatal("retained closed reader performed lookup", e, calls.Load())
	}
}
