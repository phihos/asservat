package integration

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// A goroutine that blocks forever, as a cleanup waiting on a channel nobody
// closes; the dump must name it.
func hangWatchdogBlockedHelper(block chan struct{}) { <-block }

func TestHangWatchdogDumpsAfterFailureGrace(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	go hangWatchdogBlockedHelper(block)
	var failed atomic.Bool
	out := &lockedBuffer{}
	stop := startHangWatchdog(failed.Load, "unit", 50*time.Millisecond, time.Hour, 5*time.Millisecond, out)
	defer stop()
	time.Sleep(100 * time.Millisecond)
	if out.String() != "" {
		t.Fatal("dumped before any failure or budget:", out.String())
	}
	failed.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "end of goroutine dump") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := out.String()
	if !strings.Contains(got, "unit failed") || !strings.Contains(got, "hangWatchdogBlockedHelper") {
		t.Fatalf("missing failure dump naming the blocked goroutine:\n%.2000s", got)
	}
	time.Sleep(100 * time.Millisecond)
	if n := strings.Count(out.String(), "goroutines:"); n != 1 {
		t.Fatal("expected exactly one failure dump, got", n)
	}
}

func TestHangWatchdogDumpsPastSoftBudgetWithoutFailure(t *testing.T) {
	out := &lockedBuffer{}
	stop := startHangWatchdog(func() bool { return false }, "unit", time.Hour, 30*time.Millisecond, 5*time.Millisecond, out)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "end of goroutine dump") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	if !strings.Contains(out.String(), "unit still running past its 30ms soft budget") {
		t.Fatalf("missing budget dump:\n%.500s", out.String())
	}
}

func TestHangWatchdogStopsQuietlyAndPromptly(t *testing.T) {
	out := &lockedBuffer{}
	stop := startHangWatchdog(func() bool { return true }, "unit", time.Hour, time.Hour, time.Millisecond, out)
	time.Sleep(20 * time.Millisecond)
	began := time.Now()
	stop()
	if time.Since(began) > time.Second || out.String() != "" {
		t.Fatal("stop must end the watch without a dump", time.Since(began), out.String())
	}
}

func TestInstalledContinuationSoftBudgetsCoverEveryFocus(t *testing.T) {
	if installedContinuationSoftBudget("live-observation") != installedContinuationDefaultBudget || installedContinuationSoftBudget("manual-profile") <= installedContinuationDefaultBudget {
		t.Fatal("unexpected focus budgets")
	}
	for focus, budget := range installedContinuationBudget {
		// A CI focus budget past the 20-minute job would never fire there.
		if focus != "" && (budget < 5*time.Minute || budget > 16*time.Minute) {
			t.Fatal("implausible soft budget", focus, budget)
		}
	}
}
