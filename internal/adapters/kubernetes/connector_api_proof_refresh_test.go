package kubernetes

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// ADR-251 background refresh. Synthetic completed proofs stand for separately
// qualified native productions; only the coalescing state is under test.

type refreshClock struct{ at atomic.Int64 }

func newRefreshClock(t time.Time) *refreshClock {
	c := &refreshClock{}
	c.at.Store(t.UnixNano())
	return c
}
func (c *refreshClock) now() time.Time      { return time.Unix(0, c.at.Load()).UTC() }
func (c *refreshClock) set(t time.Time)     { c.at.Store(t.UnixNano()) }
func (c *refreshClock) add(d time.Duration) { c.set(c.now().Add(d)) }

func cachedOf(s *connectorAPIProofState) *connectorAPIProof {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == nil {
		return nil
	}
	c := *s.cached
	return &c
}

func refreshing(s *connectorAPIProofState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refresh != nil
}

// waitFor polls a condition the loop reaches asynchronously; it never sleeps
// to stand for ordering, only to bound the wait.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func seedProof(t *testing.T, s *connectorAPIProofState, clock *refreshClock, p connectorAPIProof) connectorAPIProof {
	t.Helper()
	got, err := s.read(context.Background(), clock.now, func(context.Context) (connectorAPIProof, error) { return p, nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestConnectorAPIProofRefreshRebuildsBeforeExpiryOnlyUnderDemand(t *testing.T) {
	start := time.Now().UTC()
	clock := newRefreshClock(start)
	var s connectorAPIProofState
	first := seedProof(t, &s, clock, connectorCachedProof(t, start))
	successor := connectorCachedProof(t, start.Add(2*time.Second))
	var produced atomic.Int64
	produce := func(context.Context) (connectorAPIProof, error) { produced.Add(1); return successor, nil }

	// Not yet below the threshold, or never read: nothing is rebuilt.
	s.demand()
	s.rebuild(context.Background(), clock.now, 3*time.Second, produce)
	clock.add(2500 * time.Millisecond)
	s.mu.Lock()
	s.demanded = false
	s.mu.Unlock()
	s.rebuild(context.Background(), clock.now, 3*time.Second, produce)
	if produced.Load() != 0 {
		t.Fatal("rebuilt a proof that was not near its end or not read", produced.Load())
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.refreshLoop(ctx, clock.now, 3*time.Second, produce) }()
	s.demand()
	waitFor(t, "successor", func() bool { c := cachedOf(&s); return c != nil && c.observedAt.Equal(successor.observedAt) })
	c := cachedOf(&s)
	if produced.Load() != 1 || !c.validUntil.Equal(successor.validUntil) || !first.validUntil.Equal(start.Add(5*time.Second)) {
		t.Fatal("successor changed bounds or rebuilt more than once", produced.Load(), c.validUntil)
	}
	// The successor is not read: no further rebuild follows, even when due.
	clock.set(successor.validUntil.Add(-time.Second))
	s.wake <- struct{}{}
	waitFor(t, "loop idle", func() bool { return len(s.wake) == 0 })
	if produced.Load() != 1 {
		t.Fatal("rebuilt an unread proof", produced.Load())
	}
	cancel()
	<-done
}

func TestConnectorAPIProofRefreshIsSingleFlightAndRequestsDoNotWait(t *testing.T) {
	start := time.Now().UTC()
	clock := newRefreshClock(start)
	var s connectorAPIProofState
	held := seedProof(t, &s, clock, connectorCachedProof(t, start))
	successor := connectorCachedProof(t, start.Add(time.Second))
	entered, release := make(chan struct{}), make(chan struct{})
	var produced atomic.Int64
	produce := func(ctx context.Context) (connectorAPIProof, error) {
		if produced.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
			return successor, nil
		case <-ctx.Done():
			return connectorAPIProof{}, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.refreshLoop(ctx, clock.now, 5*time.Second, produce) }()
	s.demand()
	<-entered

	// A request with a valid cached proof rechecks that proof while the
	// rebuild is blocked, and its own production is never invoked.
	var checks atomic.Int64
	requestProduce := func(context.Context) (connectorAPIProof, error) {
		t.Error("request produced while a valid proof was cached")
		return connectorAPIProof{}, cfg.ErrUnavailable
	}
	check := func(_ context.Context, p connectorAPIProof) (connectorAPIProof, error) { checks.Add(1); return p, nil }
	for range 3 {
		got, err := s.read(context.Background(), clock.now, requestProduce, check)
		if err != nil || !got.observedAt.Equal(held.observedAt) || !got.validUntil.Equal(held.validUntil) {
			t.Fatal("request waited for or took the rebuild", err)
		}
		s.demand()
	}
	if checks.Load() != 3 || produced.Load() != 1 || !refreshing(&s) {
		t.Fatal("rebuild was not single-flight", checks.Load(), produced.Load())
	}
	clock.set(successor.observedAt) // the rebuild took one second
	close(release)
	waitFor(t, "successor", func() bool { c := cachedOf(&s); return c != nil && c.observedAt.Equal(successor.observedAt) })
	if !held.validUntil.Equal(start.Add(5 * time.Second)) {
		t.Fatal("rebuild changed the held proof")
	}
	cancel()
	<-done
}

func TestConnectorAPIProofRequestWithoutValidProofJoinsRebuild(t *testing.T) {
	start := time.Now().UTC()
	clock := newRefreshClock(start)
	var s connectorAPIProofState
	seedProof(t, &s, clock, connectorCachedProof(t, start))
	successor := connectorCachedProof(t, start.Add(4*time.Second))
	entered, release := make(chan struct{}), make(chan struct{})
	var produced atomic.Int64
	produce := func(context.Context) (connectorAPIProof, error) {
		produced.Add(1)
		close(entered)
		<-release
		return successor, nil
	}
	s.demand()
	rebuilt := make(chan struct{})
	go func() { defer close(rebuilt); s.rebuild(context.Background(), clock.now, 5*time.Second, produce) }()
	<-entered
	clock.set(start.Add(5 * time.Second)) // the cached proof has ended
	got := make(chan error, 1)
	go func() {
		p, err := s.read(context.Background(), clock.now, func(context.Context) (connectorAPIProof, error) {
			produced.Add(1)
			return connectorAPIProof{}, cfg.ErrUnavailable
		}, nil)
		if err == nil && !p.observedAt.Equal(successor.observedAt) {
			err = cfg.ErrChanged
		}
		got <- err
	}()
	waitFor(t, "request joined the rebuild", func() bool { c := cachedOf(&s); return c == nil })
	close(release)
	if err := <-got; err != nil || produced.Load() != 1 {
		t.Fatal("request did not join the single rebuild", err, produced.Load())
	}
	<-rebuilt
}

func TestConnectorAPIProofRefreshNeverReplacesFresherOrExtendsBounds(t *testing.T) {
	start := time.Now().UTC()
	clock := newRefreshClock(start)
	var s connectorAPIProofState
	held := seedProof(t, &s, clock, connectorCachedProof(t, start))
	successor := connectorCachedProof(t, start.Add(time.Second))
	// A recheck of the held proof that completes after the successor entered
	// narrows only its caller's copy; the fresher successor stays cached.
	entered, release := make(chan struct{}), make(chan struct{})
	check := func(_ context.Context, p connectorAPIProof) (connectorAPIProof, error) {
		close(entered)
		<-release
		p.validUntil = p.validUntil.Add(-time.Second)
		return p, nil
	}
	got := make(chan connectorAPIProof, 1)
	go func() {
		p, err := s.read(context.Background(), clock.now, nil, check)
		if err != nil {
			t.Error(err)
		}
		got <- p
	}()
	<-entered
	clock.set(successor.observedAt)
	s.demand()
	s.rebuild(context.Background(), clock.now, 5*time.Second, func(context.Context) (connectorAPIProof, error) { return successor, nil })
	close(release)
	narrowed := <-got
	c := cachedOf(&s)
	if !narrowed.observedAt.Equal(held.observedAt) || !narrowed.validUntil.Equal(held.validUntil.Add(-time.Second)) || c == nil || !c.observedAt.Equal(successor.observedAt) || !c.validUntil.Equal(successor.validUntil) {
		t.Fatal("recheck replaced the fresher successor or bounds changed")
	}
	// An older rebuilt proof cannot displace a fresher cached one either.
	s.demand()
	s.rebuild(context.Background(), clock.now, 5*time.Second, func(context.Context) (connectorAPIProof, error) { return held, nil })
	if c = cachedOf(&s); !c.observedAt.Equal(successor.observedAt) {
		t.Fatal("older proof displaced the freshest")
	}
	// A rebuild that tries to renew past five seconds is refused and, like a
	// failed request production, leaves no proof usable.
	renewed := successor
	renewed.validUntil = renewed.validUntil.Add(time.Second)
	s.demand()
	s.rebuild(context.Background(), clock.now, 5*time.Second, func(context.Context) (connectorAPIProof, error) { return renewed, nil })
	if cachedOf(&s) != nil {
		t.Fatal("renewing rebuild was accepted")
	}
}

func TestConnectorAPIProofRefreshFailureOrChangeInvalidates(t *testing.T) {
	for _, mode := range []string{"error", "invalidated"} {
		t.Run(mode, func(t *testing.T) {
			start := time.Now().UTC()
			clock := newRefreshClock(start)
			var s connectorAPIProofState
			seedProof(t, &s, clock, connectorCachedProof(t, start))
			s.demand()
			produce := func(ctx context.Context) (connectorAPIProof, error) {
				if mode == "error" {
					return connectorAPIProof{}, cfg.ErrChanged
				}
				s.invalidate()
				if ctx.Err() == nil {
					t.Error("invalidation did not cancel the rebuild")
				}
				return connectorCachedProof(t, start), nil
			}
			s.rebuild(context.Background(), clock.now, 5*time.Second, produce)
			if cachedOf(&s) != nil || refreshing(&s) {
				t.Fatal("failed or invalidated rebuild left a usable proof")
			}
		})
	}
}

func TestConnectorAPIProofRefreshStopsOnShutdown(t *testing.T) {
	start := time.Now().UTC()
	clock := newRefreshClock(start)
	var s connectorAPIProofState
	seedProof(t, &s, clock, connectorCachedProof(t, start))
	entered := make(chan struct{})
	produce := func(ctx context.Context) (connectorAPIProof, error) {
		close(entered)
		<-ctx.Done()
		return connectorAPIProof{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.refreshLoop(ctx, clock.now, 5*time.Second, produce) }()
	s.demand()
	<-entered
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh loop did not stop with its rebuild")
	}
	if refreshing(&s) {
		t.Fatal("rebuild outlived shutdown")
	}
	// An idle loop also returns at once.
	idle, stop := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() { defer close(finished); s.refreshLoop(idle, clock.now, 5*time.Second, produce) }()
	stop()
	<-finished
}
