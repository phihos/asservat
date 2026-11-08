package capture

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

// coldStorage models installed run 42460732876: the binding expired while no
// demand was active; the demanded hub-worker refresh landed 4.5 s later, after
// the preview phase's readiness cutoff (5 s minus the response reserve).
type coldStorage struct {
	f        *investigationFixture
	mu       sync.Mutex
	landedAt time.Time // real time; zero until the first demand
	land     time.Duration
	demands  int
}

func (c *coldStorage) DemandCapacityRefresh(context.Context, targets.Request) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.demands++
	if c.landedAt.IsZero() {
		c.landedAt = time.Now().Add(c.land)
	}
	return nil
}

func (c *coldStorage) ContextStorage(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
	out, err := c.f.ContextStorage(ctx, target)
	c.mu.Lock()
	landed := !c.landedAt.IsZero() && !time.Now().Before(c.landedAt)
	c.mu.Unlock()
	if landed {
		out.Binding.ObservedAt = c.f.now
		out.Binding.FreshUntil = c.f.now.Add(30 * time.Second)
		return out, err
	}
	out.Binding.ObservedAt = c.f.now.Add(-31 * time.Second)
	out.Binding.FreshUntil = c.f.now.Add(-time.Second)
	return out, value.ErrStorageBindingExpired
}

// A preview that finds a cold binding gets one more complete attempt, with
// every fact read again, when the refresh it demanded lands after the first
// attempt's readiness cutoff and the operation's request window still has
// room. Without that room the original refusal stands.
func TestContextPreviewRetriesColdStorageWithinRequestWindow(t *testing.T) {
	for _, mode := range []string{"room", "no-room"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationFixture()
			cold := &coldStorage{f: f, land: 4500 * time.Millisecond}
			f.svc.Storage, f.svc.Refresh = cold, cold
			var failures []string
			f.svc.ReportPreviewFailure = func(stage string) { failures = append(failures, stage) }
			window := 15 * time.Second
			if mode == "no-room" {
				window = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(t.Context(), window)
			defer cancel()
			deadline, _ := ctx.Deadline()
			r, err := f.svc.Preview(ctx, f.source(t, ctx), f.intent())
			if time.Now().After(deadline) {
				t.Fatal("preview ran past the request window")
			}
			if len(failures) == 0 || failures[0] != storageReadinessTailStage {
				t.Fatal("first attempt did not end at the readiness tail", failures)
			}
			if mode == "no-room" {
				if !errors.Is(err, value.ErrStorageBindingExpired) || f.targetReads.Load() != 1 {
					t.Fatal("retried without room in the request window", err, f.targetReads.Load())
				}
				return
			}
			if err != nil {
				t.Fatal("cold storage refused a preview with room for one more attempt", err, failures)
			}
			if f.targetReads.Load() != 2 || r.Preview.Storage != f.store.Selection {
				t.Fatal("second attempt did not read every fact again", f.targetReads.Load())
			}
		})
	}
}
