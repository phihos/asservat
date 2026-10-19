package presentation

import (
	"strings"
	"testing"
	"time"
)

func TestCallTimingReportsOnlyReachedStagesInBuckets(t *testing.T) {
	start := time.Now().Add(-4 * time.Second)
	var got string
	callTiming{start: start, admitted: start.Add(50 * time.Millisecond), begin: start.Add(1500 * time.Millisecond)}.report("normal", func(s string) { got = s })
	if !strings.HasPrefix(got, "normal pre@<100ms begin@<2s total@>=3s") || strings.Contains(got, "call") || strings.Contains(got, "finish") {
		t.Fatalf("stopped at begin: %q", got)
	}
	callTiming{}.report("normal", nil) // no reporter is a no-op
	if durationBucket(time.Time{}, start) != "@none" {
		t.Fatal("unreached stage")
	}
}
