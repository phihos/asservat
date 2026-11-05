package capture

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

// A short caller still gets an authoritative read. Only optional readiness
// waiting is skipped; sufficient fresh storage remains usable in the tail.
func TestContextStorageResponseReserveTail(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "thin", true: "fresh"}[fresh], func(t *testing.T) {
			f, facts, owner := consumptionFixture(t)
			refresh := &countingRefresh{}
			f.svc.Refresh = refresh
			var reads atomic.Int32
			f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
				reads.Add(1)
				if until, _ := ctx.Deadline(); time.Until(until) < 400*time.Millisecond {
					t.Error("authoritative read received readiness cutoff")
				}
				out, err := f.ContextStorage(ctx, target)
				if !fresh {
					out.Binding.FreshUntil = f.now.Add(500 * time.Millisecond)
				}
				return out, err
			})
			ctx, cancel := context.WithTimeout(t.Context(), 750*time.Millisecond)
			defer cancel()
			started := time.Now()
			_, err := f.svc.consumeStorage(ctx, facts, f.intent(), owner)
			if fresh && err != nil || !fresh && !errors.Is(err, value.ErrUnavailable) {
				t.Fatal("unexpected result", err)
			}
			if time.Since(started) > 300*time.Millisecond || ctx.Err() != nil || reads.Load() != 1 || refresh.demands.Load() != 0 {
				t.Fatal("tail readiness consumed reply time", time.Since(started), ctx.Err(), reads.Load(), refresh.demands.Load())
			}
		})
	}
}

// A cold hint joins at the scheduling cutoff. Its blocked read must not
// submit demand after cancellation, and consumption still reads independently.
func TestContextStorageResponseReserveJoinsHint(t *testing.T) {
	f, facts, _ := consumptionFixture(t)
	refresh := &countingRefresh{}
	f.svc.Refresh = refresh
	var reads atomic.Int32
	exited := make(chan struct{})
	f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
		if reads.Add(1) == 1 {
			defer close(exited)
			<-ctx.Done()
			return ContextStorageObservation{}, ctx.Err()
		}
		out, err := f.ContextStorage(ctx, target)
		out.Binding.FreshUntil = f.now.Add(500 * time.Millisecond)
		return out, err
	})
	ctx, cancel := context.WithTimeout(t.Context(), 1250*time.Millisecond)
	defer cancel()
	owner := f.svc.beginStorageWait(ctx, facts.target, f.now.Add(5*time.Second), f.store.Selection)
	defer owner.close()
	started := time.Now()
	_, err := f.svc.consumeStorage(ctx, facts, f.intent(), owner)
	if !errors.Is(err, value.ErrUnavailable) || ctx.Err() != nil || time.Since(started) > 700*time.Millisecond || reads.Load() != 2 || refresh.demands.Load() != 0 {
		t.Fatal("cold readiness exhausted response window", err, ctx.Err(), time.Since(started), reads.Load(), refresh.demands.Load())
	}
	select {
	case <-exited:
	default:
		t.Fatal("hint not joined")
	}
}

func TestContextStorageResponseReserveFinalFreshRead(t *testing.T) {
	f, facts, _ := consumptionFixture(t)
	var reads, demands atomic.Int32
	f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
		out, err := f.ContextStorage(ctx, target)
		if reads.Add(1) == 1 {
			out.Binding.FreshUntil = f.now.Add(500 * time.Millisecond)
		}
		return out, err
	})
	f.svc.Refresh = consumptionRefreshFunc(func(ctx context.Context, _ targets.Request) error {
		demands.Add(1)
		<-ctx.Done()
		// A nil submission result is not refresh acknowledgement. Only the
		// independently fresh consumption read below can permit progress.
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 1250*time.Millisecond)
	defer cancel()
	owner := f.svc.beginStorageWait(ctx, facts.target, f.now.Add(5*time.Second), f.store.Selection)
	defer owner.close()
	_, err := f.svc.consumeStorage(ctx, facts, f.intent(), owner)
	if err != nil || ctx.Err() != nil || reads.Load() != 2 || demands.Load() != 1 {
		t.Fatal("omitted independent final read or repeated wait", err, ctx.Err(), reads.Load(), demands.Load())
	}
}

func TestContextStorageResponseReserveSkipsTailHint(t *testing.T) {
	f, facts, _ := consumptionFixture(t)
	var reads atomic.Int32
	refresh := &countingRefresh{}
	f.svc.Refresh = refresh
	f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
		reads.Add(1)
		return f.ContextStorage(ctx, target)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 750*time.Millisecond)
	defer cancel()
	owner := f.svc.beginStorageWait(ctx, facts.target, f.now.Add(5*time.Second), f.store.Selection)
	defer owner.close()
	select {
	case <-owner.done:
	default:
		t.Fatal("tail hint started")
	}
	if reads.Load() != 0 || refresh.demands.Load() != 0 {
		t.Fatal("tail hint performed I/O")
	}
	if _, err := f.svc.consumeStorage(ctx, facts, f.intent(), owner); err != nil || reads.Load() != 1 {
		t.Fatal("tail lost fresh authoritative read", err, reads.Load())
	}
}

// An upfront possible-profile hint may be longer than the classified ordinary
// request. It must join at that request's existing reply reserve, not consume
// its entire authority interval while waiting for the hint's longer context.
func TestContextStorageResponseReserveJoinsLongerHint(t *testing.T) {
	f, facts, _ := consumptionFixture(t)
	var reads, demands atomic.Int32
	joined := make(chan struct{})
	f.svc.Refresh = consumptionRefreshFunc(func(context.Context, targets.Request) error { demands.Add(1); return nil })
	f.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
		if reads.Add(1) == 1 {
			defer close(joined)
			<-ctx.Done()
			return ContextStorageObservation{}, ctx.Err()
		}
		out, err := f.ContextStorage(ctx, target)
		out.Binding.FreshUntil = f.now.Add(500 * time.Millisecond)
		return out, err
	})
	candidate, cancelCandidate := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancelCandidate()
	owner := f.svc.beginStorageWait(candidate, facts.target, f.now.Add(5*time.Second), f.store.Selection)
	defer owner.close()
	ordinary, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	started := time.Now()
	_, err := f.svc.consumeStorage(ordinary, facts, f.intent(), owner)
	if !errors.Is(err, value.ErrUnavailable) || ordinary.Err() != nil || time.Since(started) > 4600*time.Millisecond || reads.Load() != 2 || demands.Load() != 0 {
		t.Fatal("ordinary reply reserve lost to candidate hint", err, ordinary.Err(), time.Since(started), reads.Load(), demands.Load())
	}
	select {
	case <-joined:
	default:
		t.Fatal("classified hint not joined")
	}
}

// The original five-second request and source facts stay fixed. A separately
// published binding becomes current 125 ms after the old four-second readiness
// cutoff. Advance only the test clock at the joined hint's actual cutoff, so
// scheduler delays cannot make the old reserve accidentally observe publication.
func TestContextStorageResponseReservePublicationBoundary(t *testing.T) {
	for _, mode := range []string{"fresh", "source-expired", "selection-changed"} {
		t.Run(mode, func(t *testing.T) {
			f, facts, _ := consumptionFixture(t)
			origin := f.now
			originalEnd := origin.Add(5 * time.Second)
			if mode == "source-expired" {
				facts.target.FreshUntil = origin.Add(4100 * time.Millisecond)
			}
			sourceEnds := []time.Time{facts.target.FreshUntil, facts.eligibility.ValidUntil, facts.eligibility.VerifiedIdentity.ValidUntil, facts.capability.FreshUntil, facts.retention.ValidUntil, facts.retention.Proof.ValidUntil}
			var clock atomic.Int64
			clock.Store(origin.UnixNano())
			f.svc.Now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			expired := f.store
			expired.Binding.ObservedAt, expired.Binding.FreshUntil = origin.Add(-31*time.Second), origin.Add(-time.Second)
			fresh := f.store
			published := originalEnd.Add(-time.Second).Add(125 * time.Millisecond)
			fresh.Binding.ObservedAt, fresh.Binding.FreshUntil = published, published.Add(30*time.Second)
			if mode == "selection-changed" {
				fresh.Selection.AllocationRevision++
			}
			var hints, finals, demands atomic.Int32
			var finalDeadline time.Time
			f.svc.Refresh = consumptionRefreshFunc(func(context.Context, targets.Request) error { demands.Add(1); return nil })
			f.svc.Storage = consumptionStorageFunc(func(call context.Context, _ authorization.Target) (ContextStorageObservation, error) {
				end, _ := call.Deadline()
				if end.Before(originalEnd) && hints.Add(1) <= 2 {
					if hints.Load() == 1 {
						return expired, value.ErrStorageBindingExpired
					}
					<-call.Done()
					// An earlier source bound cancels the hint before its scheduling end.
					if facts.target.FreshUntil.Before(end) {
						end = facts.target.FreshUntil
					}
					clock.Store(end.UnixNano())
					return ContextStorageObservation{}, call.Err()
				}
				finals.Add(1)
				finalDeadline = end
				if f.svc.Now().Before(published) {
					return expired, value.ErrStorageBindingExpired
				}
				return fresh, nil
			})
			ctx, cancel := context.WithDeadline(t.Context(), originalEnd)
			defer cancel()
			owner := f.svc.beginStorageWait(ctx, facts.target, originalEnd, f.store.Selection)
			defer owner.close()
			out, err := f.svc.consumeStorage(ctx, facts, f.intent(), owner)
			if mode == "fresh" {
				if err != nil || out.Selection != f.store.Selection || !finalDeadline.Equal(originalEnd) || finals.Load() != 1 {
					t.Fatal("independent publication missed unchanged request", err, finals.Load())
				}
			} else if !errors.Is(err, value.ErrChanged) && !(mode == "source-expired" && errors.Is(err, context.DeadlineExceeded)) {
				t.Fatal("expired facts or changed selection accepted", mode, err)
			}
			end, _ := ctx.Deadline()
			afterEnds := []time.Time{facts.target.FreshUntil, facts.eligibility.ValidUntil, facts.eligibility.VerifiedIdentity.ValidUntil, facts.capability.FreshUntil, facts.retention.ValidUntil, facts.retention.Proof.ValidUntil}
			for i := range sourceEnds {
				if !sourceEnds[i].Equal(afterEnds[i]) {
					t.Fatal("source end changed", i)
				}
			}
			if !end.Equal(originalEnd) || !owner.until.Equal(originalEnd) || ctx.Err() != nil || hints.Load() != 2 || demands.Load() != 1 {
				t.Fatal("request/demand ownership changed", ctx.Err(), hints.Load(), demands.Load())
			}
			if mode == "source-expired" && finals.Load() != 0 {
				t.Fatal("read after original source expiry", finals.Load())
			}
			t.Logf("mode=%s request5s unchanged; one hint/demand; publication oldcutoff+125ms; final tail=%s", mode, time.Until(originalEnd).Round(time.Millisecond))
		})
	}
}
