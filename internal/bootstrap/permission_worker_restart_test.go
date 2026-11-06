package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
)

// Only the already-owned Begin/failed LIST/Suspend path is synthetic here.
// The result is produced by the real reconciler, not a fabricated scheduling
// flag. It cannot authorize a successor's SQL epoch or source observations.
type permissionRestartFixture struct {
	app.PermissionStore
	now                    time.Time
	fence                  value.PermissionFence
	begin, suspend         int
	trustErr, suspendErr   error
	cancelDuringSuspension context.CancelFunc
}

func (f *permissionRestartFixture) PermissionTrust(context.Context) (app.PermissionTrust, error) {
	return app.PermissionTrust{Digest: artifact.Digest{1}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, f.trustErr
}
func (f *permissionRestartFixture) PermissionSnapshot(context.Context) (value.Snapshot, error) {
	return value.Snapshot{}, value.ErrUnavailable
}
func (*permissionRestartFixture) WatchBindings(context.Context, string) (app.BindingWatch, error) {
	panic("failed LIST must not start a watch")
}
func (f *permissionRestartFixture) BeginPermissions(_ context.Context, root, epoch string, digest artifact.Digest) (value.PermissionFence, error) {
	f.begin++
	f.fence = value.PermissionFence{RootID: root, Epoch: epoch, TrustDigest: digest, LeaseUntil: f.now.Add(30 * time.Second)}
	return f.fence, nil
}
func (f *permissionRestartFixture) SuspendPermissions(_ context.Context, fence value.PermissionFence) error {
	f.suspend++
	if fence != f.fence {
		panic("suspension changed original owned epoch")
	}
	if f.cancelDuringSuspension != nil {
		f.cancelDuringSuspension()
	}
	return f.suspendErr
}

func TestPermissionWorkerRestartUsesCompletedSuspension(t *testing.T) {
	for _, name := range []string{"confirmed", "unknown", "no-epoch", "parent-canceled"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f := &permissionRestartFixture{now: time.Now()}
			want := 31 * time.Second
			switch name {
			case "confirmed":
				want = time.Second
			case "unknown":
				f.suspendErr = value.ErrUnavailable
			case "no-epoch":
				f.trustErr = value.ErrUnavailable
			case "parent-canceled":
				f.cancelDuringSuspension = cancel
			}
			const root = "11111111-1111-4111-8111-111111111111"
			r := app.BindingReconciler{RootID: root, Reader: f, Watcher: f, Trust: f, Store: f, Now: time.Now, NewID: func() string { return root }}
			result := r.RunEpoch(ctx)
			if !errors.Is(result.Err, value.ErrUnavailable) || result.Suspended != (name == "confirmed") || permissionEpochRestartDelay(result) != want {
				t.Fatal("completed epoch chose wrong restart schedule", result.Suspended, permissionEpochRestartDelay(result), result.Err)
			}
			wantCalls := 1
			if name == "no-epoch" {
				wantCalls = 0
			}
			if f.begin != wantCalls || f.suspend != wantCalls {
				t.Fatal("missing epoch was suspended or original suspension repeated", f.begin, f.suspend)
			}
			if name == "parent-canceled" && sleepContext(ctx, permissionEpochRestartDelay(result)) {
				t.Fatal("parent cancellation permitted a restart")
			}
		})
	}
}
