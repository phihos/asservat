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
