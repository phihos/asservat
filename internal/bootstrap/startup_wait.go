package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Startup waits for dependencies that another component creates after this
// one starts (an offer ConfigMap, setup-written SQL rows, a provider mount):
// the process retries in place with bounded backoff instead of exiting into
// the kubelet's crash back-off. Readiness stays false until the attempt
// succeeds because the caller has not started serving yet.
var (
	startupWaitFirst = time.Second
	startupWaitMax   = 30 * time.Second
)

// startupLog writes waitStartup's closed lines to the process log.
func startupLog(line string) { fmt.Fprintln(os.Stderr, line) }

// startupRetryable keeps genuine configuration faults fatal: invalid, changed
// or denied content does not heal by waiting.
func startupRetryable(err error) bool {
	return !errors.Is(err, cfg.ErrInvalid) && !errors.Is(err, cfg.ErrChanged) && !errors.Is(err, cfg.ErrDenied)
}

// waitStartup runs attempt until it succeeds, returns a non-retryable error
// or ctx ends. It logs the first failure at each fixed sub-step and the first
// success after a failure, never every retry. retryable nil means startupRetryable.
func waitStartup(ctx context.Context, step string, logf func(string), attempt func(context.Context) error, retryable func(error) bool) error {
	if retryable == nil {
		retryable = startupRetryable
	}
	delay, failures, last := startupWaitFirst, 0, ""
	for {
		err := attempt(ctx)
		if err == nil {
			if failures > 0 && logf != nil {
				logf("startup " + step + ": ok after " + strconv.Itoa(failures) + " failed attempts")
			}
			return nil
		}
		if ctx.Err() != nil || !retryable(err) {
			return err
		}
		failures++
		// The fixed sub-step names which dependency is not ready yet; log it
		// once per change, never each retry and never dependency text.
		at := "unspecified"
		var inner interface{ FixedStep() string }
		if errors.As(err, &inner) {
			at = inner.FixedStep()
		}
		if at != last && logf != nil {
			logf("startup " + step + ": waiting at " + at + " (" + errorClass(err) + "), retrying with backoff")
		}
		last = at
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return err
		case <-t.C:
		}
		if delay *= 2; delay > startupWaitMax {
			delay = startupWaitMax
		}
	}
}
