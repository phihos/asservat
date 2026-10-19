package kubernetes

import (
	"testing"

	"k8s.io/client-go/rest"
)

func TestWithOpeningBurstSetsOpeningLimiter(t *testing.T) {
	original := &rest.Config{Host: "https://example.invalid"}
	c := WithOpeningBurst(original)
	if original.RateLimiter != nil || c.RateLimiter == nil || c.RateLimiter.QPS() != OpeningQPS {
		t.Fatal("opening limiter must be a copy at OpeningQPS")
	}
	for i := 0; i < OpeningBurst; i++ {
		if !c.RateLimiter.TryAccept() {
			t.Fatalf("call %d waited inside the burst", i+1)
		}
	}
	if c.RateLimiter.TryAccept() {
		t.Fatal("burst exceeded")
	}
	if WithOpeningBurst(nil) != nil {
		t.Fatal("nil config")
	}
}
