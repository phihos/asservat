package authorization

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/privacy"
)

type observationPolicyReader func(context.Context) (privacy.DownloadPolicy, error)

func (f observationPolicyReader) DownloadPolicy(ctx context.Context) (privacy.DownloadPolicy, error) {
	return f(ctx)
}

type observationProcessingReader func(context.Context, ContextDownloadEvidence, artifact.RecoveryProof) (artifact.DownloadProcessingProof, error)

func (f observationProcessingReader) ContextProcessing(ctx context.Context, r ContextDownloadEvidence, proof artifact.RecoveryProof) (artifact.DownloadProcessingProof, error) {
	return f(ctx, r, proof)
}

func TestDownloadPolicyObservationNewRequestNearExpiry(t *testing.T) {
	for _, short := range []bool{false, true} {
		name := "fresh-request"
		if short {
			name = "original-short-caller"
		}
		t.Run(name, func(t *testing.T) {
			f, s, r, actor := newEnvironmentFixture()
			var offset atomic.Int64
			offset.Store(int64(-59900 * time.Millisecond))
			now := func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
			var reads int
			reader := policyObservationForTest(t, observationPolicyReader(func(context.Context) (privacy.DownloadPolicy, error) {
				reads++
				p := f.policy
				p.ObservedAt = now()
				p.FreshUntil = p.ObservedAt.Add(5 * time.Second)
				return p, nil
			}), now)
			old, err := reader.DownloadPolicy(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			offset.Store(0)
			s.Now, s.Policies = now, reader
			var processingUntil time.Time
			s.Processing = observationProcessingReader(func(ctx context.Context, evidence ContextDownloadEvidence, proof artifact.RecoveryProof) (artifact.DownloadProcessingProof, error) {
				if processingUntil.IsZero() {
					processingUntil, _ = ctx.Deadline()
					// This joined read needs only 150ms, far below the original
					// five-second request; the old cache leaves about 100ms.
					timer := time.NewTimer(150 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-ctx.Done():
						return artifact.DownloadProcessingProof{}, ctx.Err()
					case <-timer.C:
					}
				}
				return f.ContextProcessing(ctx, evidence, proof)
			})
			duration := 5 * time.Second
			if short {
				duration = 40 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), duration)
			defer cancel()
			original, _ := ctx.Deadline()
			out, err := s.DownloadEnvironment(ctx, r, actor)
			t.Logf("short=%t raw_reads=%d processing_bound_after_old=%s err=%v", short, reads, processingUntil.Sub(old.FreshUntil), err)
			if short {
				// Compare the wall clock, not ctx.Err(): a nested WithDeadline at
				// the same instant owns a separate timer, so the product can
				// observe expiry and return before this caller's timer fires.
				if err == nil || processingUntil.After(original) || time.Now().Before(original) {
					t.Fatal("refresh extended original short caller", err, processingUntil.Sub(original), time.Since(original))
				}
				return
			}
			if err != nil || reads != 2 || !out.CurrentValid(now()) || !processingUntil.After(old.FreshUntil) || out.ValidUntil.After(original) || out.ValidUntil.After(r.ValidUntil) {
				t.Fatal("near-expiry observation shortened a new request instead of refreshing", reads, err)
			}
		})
	}
}

func policyObservationForTest(t *testing.T, raw DownloadPolicyReader, now func() time.Time) DownloadPolicyReader {
	t.Helper()
	reader, err := NewDownloadPolicyObservations(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

type policyObservationClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *policyObservationClock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *policyObservationClock) Set(n time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.now = n }

func TestDownloadPolicyObservationRetainsOriginalInterval(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	clock := &policyObservationClock{now: f.now}
	original := f.now
	var reads atomic.Int32
	raw := observationPolicyReader(func(context.Context) (privacy.DownloadPolicy, error) {
		reads.Add(1)
		p := f.policy
		p.ObservedAt = clock.Now()
		p.FreshUntil = p.ObservedAt.Add(5 * time.Second)
		return p, nil
	})
	reader := policyObservationForTest(t, raw, clock.Now)
	call, end := context.WithTimeout(t.Context(), time.Second)
	defer end()
	first, err := reader.DownloadPolicy(call)
	if err != nil {
		t.Fatal(err)
	}
	clock.Set(original.Add(54 * time.Second))
	last, err := reader.DownloadPolicy(call)
	if err != nil || reads.Load() != 1 || !first.ObservedAt.Equal(original) || !last.ObservedAt.Equal(original) || !first.FreshUntil.Equal(original.Add(time.Minute)) || !last.FreshUntil.Equal(first.FreshUntil) {
		t.Fatalf("observation was reread or its original interval changed: reads=%d first=%s/%s last=%s/%s err=%v", reads.Load(), first.ObservedAt, first.FreshUntil, last.ObservedAt, last.FreshUntil, err)
	}
	clock.Set(original.Add(time.Minute))
	next, err := reader.DownloadPolicy(call)
	if err != nil || reads.Load() != 2 || !next.ObservedAt.Equal(clock.Now()) || !next.FreshUntil.Equal(original.Add(2*time.Minute)) {
		t.Fatal("expired observation did not require one new live read", reads.Load(), err)
	}
}

func TestDownloadPolicyObservationRefreshesOnlyInFinalRequestWindow(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "refresh"
		if fail {
			name = "failed-refresh-no-stale-fallback"
		}
		t.Run(name, func(t *testing.T) {
			f, _, _, _ := newEnvironmentFixture()
			clock := &policyObservationClock{now: f.now}
			failure := errors.New("live source denied")
			reads := 0
			reader := policyObservationForTest(t, observationPolicyReader(func(context.Context) (privacy.DownloadPolicy, error) {
				reads++
				if fail && reads > 1 {
					return privacy.DownloadPolicy{}, failure
				}
				p := f.policy
				p.ObservedAt = clock.Now()
				p.FreshUntil = p.ObservedAt.Add(5 * time.Second)
				return p, nil
			}), clock.Now)
			old, err := reader.DownloadPolicy(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			clock.Set(old.FreshUntil.Add(-5 * time.Second))
			exact, err := reader.DownloadPolicy(t.Context())
			if err != nil || reads != 1 || exact.ObservedAt != old.ObservedAt || exact.FreshUntil != old.FreshUntil {
				t.Fatal("exact five-second margin refreshed or slid original interval", reads, err)
			}
			clock.Set(clock.Now().Add(time.Nanosecond))
			fresh, err := reader.DownloadPolicy(t.Context())
			if fail {
				if !errors.Is(err, failure) || fresh.RootID != "" || reads != 2 {
					t.Fatal("thin valid observation reused after failed refresh", reads, err)
				}
				return
			}
			if err != nil || reads != 2 || fresh.ObservedAt != clock.Now() || fresh.FreshUntil != clock.Now().Add(time.Minute) || old.FreshUntil != old.ObservedAt.Add(time.Minute) {
				t.Fatal("refresh did not anchor to new raw observation", reads, err)
			}
		})
	}
}

func TestDownloadPolicyObservationSharesConcurrentRead(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	var reads atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	raw := observationPolicyReader(func(ctx context.Context) (privacy.DownloadPolicy, error) {
		if reads.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
			return f.policy, nil
		case <-ctx.Done():
			return privacy.DownloadPolicy{}, ctx.Err()
		}
	})
	reader := policyObservationForTest(t, raw, func() time.Time { return f.now })
	const callers = 8
	results := make(chan error, callers)
	for range callers {
		go func() { _, err := reader.DownloadPolicy(t.Context()); results <- err }()
	}
	<-entered
	close(release)
	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if reads.Load() != 1 {
		t.Fatalf("concurrent callers performed %d live policy reads, want1", reads.Load())
	}
}

func TestDownloadPolicyObservationWaiterCancellation(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	var reads atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	raw := observationPolicyReader(func(ctx context.Context) (privacy.DownloadPolicy, error) {
		if reads.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
			return f.policy, nil
		case <-ctx.Done():
			return privacy.DownloadPolicy{}, ctx.Err()
		}
	})
	reader := policyObservationForTest(t, raw, func() time.Time { return f.now })
	ownerDone := make(chan error, 1)
	go func() { _, err := reader.DownloadPolicy(t.Context()); ownerDone <- err }()
	<-entered
	waiter, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.DownloadPolicy(waiter); err == nil {
		t.Error("cancelled waiter returned authority")
	}
	close(release)
	if err := <-ownerDone; err != nil {
		t.Fatal("waiter cancelled original reader", err)
	}
	if reads.Load() != 1 {
		t.Fatalf("waiter started additional read: %d", reads.Load())
	}
}

func TestDownloadPolicyObservationOwnsReturnedSlices(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	original := f.policy.Clients[0].Purposes[0]
	reader := policyObservationForTest(t, observationPolicyReader(func(context.Context) (privacy.DownloadPolicy, error) { return f.policy, nil }), func() time.Time { return f.now })
	p, err := reader.DownloadPolicy(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	p.Clients[0].DataClasses[0] = "changed"
	p.Clients[0].PrivacyClasses[0] = "changed"
	p.Clients[0].EvidenceTypes[0] = "changed"
	p.Clients[0].Purposes[0] = "changed"
	p.Clients[0].PathIDs[0] = "changed"
	p.PermittedRegions[0] = "changed"
	p.Paths[0].StorageRegion = "changed"
	p.Operators[0].ID = "changed"
	again, err := reader.DownloadPolicy(t.Context())
	if err != nil || again.Clients[0].DataClasses[0] == "changed" || again.Clients[0].PrivacyClasses[0] == "changed" || again.Clients[0].EvidenceTypes[0] == "changed" || again.Clients[0].Purposes[0] != original || again.Clients[0].PathIDs[0] == "changed" || again.PermittedRegions[0] == "changed" || again.Paths[0].StorageRegion == "changed" || again.Operators[0].ID == "changed" || f.policy.Clients[0].Purposes[0] != original {
		t.Fatal("returned data aliases retained/source policy", err)
	}
	f.policy.Clients[0].Purposes[0] = "source changed"
	again, err = reader.DownloadPolicy(t.Context())
	if err != nil || again.Clients[0].Purposes[0] != original {
		t.Fatal("source retained an alias of the owned observation", err)
	}
}

func TestDownloadPolicyObservationRejectsClockRollback(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	clock := &policyObservationClock{now: f.now}
	var reads atomic.Int32
	reader := policyObservationForTest(t, observationPolicyReader(func(context.Context) (privacy.DownloadPolicy, error) {
		reads.Add(1)
		p := f.policy
		p.ObservedAt = clock.Now()
		p.FreshUntil = p.ObservedAt.Add(5 * time.Second)
		return p, nil
	}), clock.Now)
	if _, err := reader.DownloadPolicy(t.Context()); err != nil {
		t.Fatal(err)
	}
	clock.Set(f.now.Add(20 * time.Second))
	if _, err := reader.DownloadPolicy(t.Context()); err != nil {
		t.Fatal(err)
	}
	clock.Set(f.now.Add(10 * time.Second))
	if _, err := reader.DownloadPolicy(t.Context()); err == nil {
		t.Fatal("clock rollback accepted")
	}
	if reads.Load() != 1 {
		t.Fatal("clock rollback refreshed the original policy", reads.Load())
	}
}

func TestDownloadPolicyObservationFailureHasNoFallback(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	clock := &policyObservationClock{now: f.now}
	var reads atomic.Int32
	failure := errors.New("source unavailable")
	reader := policyObservationForTest(t, observationPolicyReader(func(context.Context) (privacy.DownloadPolicy, error) {
		if reads.Add(1) > 1 {
			return privacy.DownloadPolicy{}, failure
		}
		return f.policy, nil
	}), clock.Now)
	if _, err := reader.DownloadPolicy(t.Context()); err != nil {
		t.Fatal(err)
	}
	clock.Set(f.now.Add(time.Minute))
	if p, err := reader.DownloadPolicy(t.Context()); !errors.Is(err, failure) || p.RootID != "" {
		t.Fatal("expired policy reused after failed read", err)
	}
	if reads.Load() != 2 {
		t.Fatal("failed refresh retried", reads.Load())
	}
}

type policyWaitingContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *policyWaitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestDownloadPolicyObservationFailedFlightDoesNotRetryWaiters(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	var reads atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	failure := errors.New("source failed")
	reader := policyObservationForTest(t, observationPolicyReader(func(context.Context) (privacy.DownloadPolicy, error) {
		if reads.Add(1) == 1 {
			close(entered)
		}
		<-release
		return privacy.DownloadPolicy{}, failure
	}), func() time.Time { return f.now })
	results := make(chan error, 3)
	go func() { _, err := reader.DownloadPolicy(t.Context()); results <- err }()
	<-entered
	for range 2 {
		waiter := &policyWaitingContext{Context: t.Context(), entered: make(chan struct{})}
		go func() { _, err := reader.DownloadPolicy(waiter); results <- err }()
		<-waiter.entered // Each waiter has reached the existing flight's select.
	}
	close(release)
	for range 3 {
		if err := <-results; !errors.Is(err, failure) {
			t.Fatal("shared failure changed", err)
		}
	}
	if reads.Load() != 1 {
		t.Fatal("failed refresh silently retried", reads.Load())
	}
}

func TestDownloadPolicyObservationRejectsInvalidLiveProof(t *testing.T) {
	for _, mode := range []string{"expired", "future", "long", "unprotected", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _, _ := newEnvironmentFixture()
			switch mode {
			case "expired":
				f.policy.FreshUntil = f.now
			case "future":
				f.policy.ObservedAt = f.now.Add(time.Second)
			case "long":
				f.policy.FreshUntil = f.now.Add(6 * time.Second)
			case "unprotected":
				clear(f.policy.ProtectionDigest[:])
			case "invalid":
				f.policy.Clients = nil
			}
			reader := policyObservationForTest(t, f, func() time.Time { return f.now })
			if p, err := reader.DownloadPolicy(t.Context()); err == nil || p.RootID != "" {
				t.Fatal("invalid live observation promoted")
			}
		})
	}
}

func TestDownloadPolicyObservationCanceledReadJoinsAndCannotPopulate(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	var reads atomic.Int32
	entered, joined := make(chan struct{}), make(chan struct{})
	reader := policyObservationForTest(t, observationPolicyReader(func(ctx context.Context) (privacy.DownloadPolicy, error) {
		if reads.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
			close(joined)
		}
		return f.policy, nil // Even a late positive reply must not be published.
	}), func() time.Time { return f.now })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := reader.DownloadPolicy(ctx); done <- err }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("original cancellation lost", err)
	}
	select {
	case <-joined:
	default:
		t.Fatal("read returned before source joined")
	}
	if _, err := reader.DownloadPolicy(t.Context()); err != nil || reads.Load() != 2 {
		t.Fatal("canceled result was retained", reads.Load(), err)
	}
	before := reads.Load()
	if p, err := reader.DownloadPolicy(ctx); !errors.Is(err, context.Canceled) || p.RootID != "" || reads.Load() != before {
		t.Fatal("canceled cache hit accepted", err)
	}
}

func TestDownloadPolicyObservationWaitingCallerKeepsOwnDeadline(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	var reads atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	reader := policyObservationForTest(t, observationPolicyReader(func(ctx context.Context) (privacy.DownloadPolicy, error) {
		reads.Add(1)
		close(entered)
		select {
		case <-release:
			return f.policy, nil
		case <-ctx.Done():
			return privacy.DownloadPolicy{}, ctx.Err()
		}
	}), func() time.Time { return f.now })
	done := make(chan error, 1)
	go func() { _, err := reader.DownloadPolicy(t.Context()); done <- err }()
	<-entered
	waiter, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err := reader.DownloadPolicy(waiter)
	close(release)
	if ownerErr := <-done; ownerErr != nil {
		t.Fatal("waiting caller canceled owner", ownerErr)
	}
	if !errors.Is(err, context.DeadlineExceeded) || reads.Load() != 1 {
		t.Fatal("waiter renewed deadline or started a read", reads.Load(), err)
	}
}

func TestDownloadPolicyObservationBoundsLiveReadAndRefreshesDenial(t *testing.T) {
	f, _, _, _ := newEnvironmentFixture()
	clock := &policyObservationClock{now: f.now}
	var reads int
	reader := policyObservationForTest(t, observationPolicyReader(func(ctx context.Context) (privacy.DownloadPolicy, error) {
		reads++
		until, ok := ctx.Deadline()
		if !ok || time.Until(until) > 5*time.Second {
			t.Error("live read lacks original five-second cap")
		}
		p := cloneDownloadPolicy(f.policy)
		p.ObservedAt = clock.Now()
		p.FreshUntil = p.ObservedAt.Add(5 * time.Second)
		p.Suspended = reads > 1
		return p, nil
	}), clock.Now)
	if _, err := reader.DownloadPolicy(t.Context()); err != nil {
		t.Fatal(err)
	}
	clock.Set(f.now.Add(time.Minute))
	p, err := reader.DownloadPolicy(t.Context())
	if err != nil || !p.Suspended || reads != 2 {
		t.Fatal("new denial replaced with old allow", err)
	}
}

func TestDownloadPolicyObservationKeepsCurrentEnvironmentBoundsAndFences(t *testing.T) {
	for _, mode := range []string{"success", "recovery-change", "processing-change", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, s, r, actor := newEnvironmentFixture()
			// A valid retained configuration may precede this request by 30s.
			p := cloneDownloadPolicy(f.policy)
			p.ObservedAt = f.now.Add(-30 * time.Second)
			p.FreshUntil = p.ObservedAt.Add(time.Minute)
			s.Policies = observationPolicyReader(func(context.Context) (privacy.DownloadPolicy, error) { return p, nil })
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			cutoff, _ := ctx.Deadline()
			switch mode {
			case "recovery-change":
				f.recoveryHook = func() {
					if f.recoveryReads == 2 {
						f.recovery.Revision.Generation++
					}
				}
			case "processing-change":
				f.processingHook = func() {
					if f.processingReads == 2 {
						f.processing.Sequence++
					}
				}
			case "cancel":
				f.processingHook = cancel
			}
			out, err := s.DownloadEnvironment(ctx, r, actor)
			if mode != "success" {
				if err == nil {
					t.Fatal("retained policy bypassed current fence", mode)
				}
				return
			}
			if err != nil || !out.CurrentValid(f.now) || !out.ValidUntil.Equal(cutoff) || f.recoveryReads != 2 || f.processingReads != 2 {
				t.Fatal("retained policy changed request or current checks", out.ValidUntil, cutoff, err)
			}
		})
	}
}
