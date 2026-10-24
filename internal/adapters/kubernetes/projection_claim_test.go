package kubernetes

import (
	"testing"
	"time"
)

func TestProjectionClaimNeedsOneSecondOfOriginalValidity(t *testing.T) {
	now := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	if _, ok := projectionClaimUntil(now, now.Add(3*time.Millisecond), now.Add(time.Minute)); ok {
		t.Fatal("claim with 3 ms left")
	}
	if _, ok := projectionClaimUntil(now, now.Add(time.Minute), now.Add(time.Second)); ok {
		t.Fatal("claim at exactly one second of state validity")
	}
	until, ok := projectionClaimUntil(now, now.Add(4*time.Second), now.Add(2*time.Second))
	if !ok || !until.Equal(now.Add(2*time.Second)) {
		t.Fatalf("claim must end at the earlier original bound: %v %v", until, ok)
	}
}
