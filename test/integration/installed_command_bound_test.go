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

// installedLocalToolTimeout bounds offline reads of downloaded local files
// (tshark, capinfos, go tool pprof/trace). They normally finish in seconds;
// the ceiling leaves room for the largest paced recordings.
const installedLocalToolTimeout = 10 * time.Minute

// installedDockerTimeout bounds one docker inspect/exec/restart against an
// owned kind node or fixture container; each normally takes seconds.
const installedDockerTimeout = 2 * time.Minute

// installedOutput is exec.CommandContext(...).Output() under its own
// timeout and installedCommandWaitDelay.
func installedOutput(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	command, cancel := installedBoundedCommand(ctx, timeout, name, args...)
	defer cancel()
	return command.Output()
}

// installedCombinedOutput is the CombinedOutput form of installedOutput.
func installedCombinedOutput(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	command, cancel := installedBoundedCommand(ctx, timeout, name, args...)
	defer cancel()
	return command.CombinedOutput()
}

// installedRun is the Run form of installedOutput.
func installedRun(ctx context.Context, timeout time.Duration, name string, args ...string) error {
	command, cancel := installedBoundedCommand(ctx, timeout, name, args...)
	defer cancel()
	return command.Run()
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

func TestInstalledBoundedCommandStopsHeldPipes(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	// The child keeps stdout open for 60 s after the parent shell exits.
	command, cancel := installedBoundedCommand(t.Context(), time.Minute, "sh", "-c", "sleep 60 & echo started")
	defer cancel()
	started := time.Now()
	out, _ := command.Output()
	if elapsed := time.Since(started); elapsed > installedCommandWaitDelay+10*time.Second {
		t.Fatalf("held pipe kept Wait for %s", elapsed)
	}
	if string(out) != "started\n" {
		t.Fatalf("output %q", out)
	}

	command, cancel = installedBoundedCommand(t.Context(), 200*time.Millisecond, "sleep", "60")
	defer cancel()
	started = time.Now()
	if err := command.Run(); err == nil || time.Since(started) > 10*time.Second {
		t.Fatalf("timeout did not stop the command: %v after %s", err, time.Since(started))
	}

	never := make(chan int)
	if _, ok := installedAwait(t, "test helper", never, 10*time.Millisecond); ok {
		t.Fatal("unexpected receive")
	}
}
