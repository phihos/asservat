package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func fastStartupWait(t *testing.T) {
	first, max := startupWaitFirst, startupWaitMax
	startupWaitFirst, startupWaitMax = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() { startupWaitFirst, startupWaitMax = first, max })
}

func TestWaitStartupRetriesUnavailableAndLogsRecovery(t *testing.T) {
	fastStartupWait(t)
	var lines []string
	n := 0
	err := waitStartup(t.Context(), "demo", func(s string) { lines = append(lines, s) }, func(context.Context) error {
		if n++; n < 4 {
			return &fixedStepError{"offer", &fixedStepError{"pending", mounts.ErrUnavailable}}
		}
		return nil
	}, nil)
	if err != nil || n != 4 {
		t.Fatal(err, n)
	}
	want := []string{"startup demo: waiting at offer/pending (unavailable), retrying with backoff", "startup demo: ok after 3 failed attempts"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines %q", lines)
	}
}

func TestWaitStartupKeepsInvalidConfigurationFatal(t *testing.T) {
	fastStartupWait(t)
	n := 0
	err := waitStartup(t.Context(), "demo", nil, func(context.Context) error { n++; return &fixedStepError{"config", cfg.ErrInvalid} }, nil)
	if !errors.Is(err, cfg.ErrInvalid) || n != 1 {
		t.Fatal(err, n)
	}
}

func TestWaitStartupStopsWithContext(t *testing.T) {
	fastStartupWait(t)
	ctx, cancel := context.WithCancel(t.Context())
	n := 0
	err := waitStartup(ctx, "demo", nil, func(context.Context) error {
		if n++; n == 3 {
			cancel()
		}
		return mounts.ErrUnavailable
	}, nil)
	if err == nil || n != 3 {
		t.Fatal(err, n)
	}
}
