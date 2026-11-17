package integration

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This owns only ongoing observations of the original synthetic fixture roots.
// No request, operation, identity, evidence lifetime, revision or activation is
// renewed. The worker source joins this owner only after its exact acceptance.
// A failed refresh cancels the whole native fixture and is reported at Close.
type nativeFixtureSourceOwner struct {
	ctx       context.Context
	closeOnce sync.Once
	close     func()
	workerMu  sync.Mutex
	worker    func(context.Context) error
	// held excludes refreshes while a test deliberately changes an observed
	// source (for example a suspended permission stream) and restores it.
	held sync.Mutex
}

func newNativeFixtureSourceOwner(t *testing.T, parent context.Context, base func(context.Context) error) *nativeFixtureSourceOwner {
	t.Helper()
	o := &nativeFixtureSourceOwner{}
	o.ctx, o.close = startNativeFixtureObservations(t, parent, func(call context.Context) error {
		// Skip the tick while a test holds the sources, so a hold never
		// consumes this tick's five-second budget.
		if !o.held.TryLock() {
			return nil
		}
		defer o.held.Unlock()
		if err := base(call); err != nil {
			return err
		}
		o.workerMu.Lock()
		worker := o.worker
		o.workerMu.Unlock()
		// No callback runs while holding the hook-registration mutex.
		if worker != nil {
			return worker(call)
		}
		return nil
	})
	t.Cleanup(o.Close) // Includes setup failures before a normal defer exists.
	return o
}
func (o *nativeFixtureSourceOwner) Close() { o.closeOnce.Do(o.close) }

// Hold pauses source refreshes until the returned function runs.
func (o *nativeFixtureSourceOwner) Hold() func() {
	o.held.Lock()
	return o.held.Unlock
}
func (o *nativeFixtureSourceOwner) SetWorker(t *testing.T, observe func(context.Context) error) {
	t.Helper()
	o.workerMu.Lock()
	defer o.workerMu.Unlock()
	if observe == nil || o.worker != nil || o.ctx.Err() != nil {
		t.Fatal("native worker observation registration unavailable")
	}
	o.worker = observe
}

func startNativeScenarioSources(t *testing.T, parent context.Context, admin *pgxpool.Pool, s captureAdmissionScenario) *nativeFixtureSourceOwner {
	t.Helper()
	return newNativeFixtureSourceOwner(t, parent, func(call context.Context) error {
		if _, err := s.p.RenewPermissions(call, cfg.PermissionFence{RootID: s.batch.RootID, Epoch: s.batch.Epoch, TrustDigest: s.batch.TrustDigest}); err != nil {
			return err
		}
		batch := s.batch
		batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		batch.FreshUntil = batch.ObservedAt.Add(5 * time.Second)
		return s.p.RefreshPermissions(call, batch)
	})
}

func nativeFixtureAcceptedRetention(s captureAdmissionScenario) *retentionEffectFixture {
	return s.retention
}

func TestNativeFixtureSourceOwnerJoinsRefresh(t *testing.T) {
	for _, end := range []string{"close", "parent-cancel", "setup-goexit"} {
		t.Run(end, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			entered, joined := make(chan struct{}), make(chan struct{})
			refresh := func(ctx context.Context) error {
				if calls.Add(1) == 1 {
					return nil
				}
				close(entered)
				<-ctx.Done()
				close(joined)
				return ctx.Err()
			}
			var owner *nativeFixtureSourceOwner
			t.Run("setup", func(t *testing.T) {
				owner = newNativeFixtureSourceOwner(t, parent, refresh)
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("fixture refresh never entered")
				}
				switch end {
				case "close":
					owner.Close()
				case "parent-cancel":
					cancel()
					owner.Close()
				case "setup-goexit":
					t.Skip("exercise the cleanup path used by setup Goexit")
				}
			})
			select {
			case <-joined:
			default:
				t.Fatal("source cleanup returned before the admitted refresh joined")
			}
			if owner.ctx.Err() == nil {
				t.Fatal("closed owner retained live fixture context")
			}
			owner.Close() // Multiple cleanup owners still join one original loop.
		})
	}
}
