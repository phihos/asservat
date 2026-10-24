package presentation

import (
	"context"
	"strings"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
)

func TestCallTimingReportsOnlyReachedStagesInBuckets(t *testing.T) {
	start := time.Now().Add(-4 * time.Second)
	var event, got string
	callTiming{start: start, admitted: start.Add(50 * time.Millisecond), begin: start.Add(1500 * time.Millisecond)}.report("normal", nil, func(key, timing string) { event, got = key, timing })
	if event != "normal" || !strings.HasPrefix(got, "pre@<100ms begin@<2s total@>=3s") || strings.Contains(got, "call") || strings.Contains(got, "finish") {
		t.Fatalf("stopped at begin: %q", got)
	}
	callTiming{}.report("normal", nil, nil) // no reporter is a no-op
	ctx, steps := auditapp.WithStepTimes(context.Background())
	auditapp.MarkStep(ctx, "seal", time.Now())
	callTiming{start: start, admitted: start}.report("normal", steps, func(key, timing string) { event, got = key, timing })
	if event != "normal" || !strings.HasSuffix(got, "[seal@<100ms]") {
		t.Fatalf("audit steps: %q", got)
	}
	if durationBucket(time.Time{}, start) != "@none" {
		t.Fatal("unreached stage")
	}
}
