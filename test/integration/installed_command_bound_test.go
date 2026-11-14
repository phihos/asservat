package integration

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// installedCommandWaitDelay bounds Wait after the command's context ends or
// the process exits while a child (Chromium, a kubectl/docker stream) still
// holds its output pipes.
const installedCommandWaitDelay = 5 * time.Second

// installedBoundedCommand runs an external tool from an installed journey
// under its own ceiling: the journey context lasts up to 45 minutes, which
// would otherwise let one stuck helper consume the CI job limit. The timeout
// is a hang bound sized well above the step's normal runtime, never a
// product deadline. Callers must call the returned cancel.
func installedBoundedCommand(ctx context.Context, timeout time.Duration, name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	call, cancel := context.WithTimeout(ctx, timeout)
	command := exec.CommandContext(call, name, args...)
	command.WaitDelay = installedCommandWaitDelay
	return command, cancel
}

// installedAwait receives one value from a helper goroutine during cleanup,
// giving up after limit so a stuck helper is reported instead of holding the
// test until the CI job is cancelled without logs.
func installedAwait[T any](t testing.TB, helper string, ch <-chan T, limit time.Duration) (T, bool) {
	t.Helper()
	select {
	case v := <-ch:
		return v, true
	case <-time.After(limit):
		t.Logf("%s did not finish within %s; continuing cleanup", helper, limit)
		var zero T
		return zero, false
	}
}
