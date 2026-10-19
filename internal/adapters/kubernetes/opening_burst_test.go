package kubernetes

import (
	"testing"

	"k8s.io/client-go/rest"
)

func TestWithOpeningBurstKeepsRateAndRaisesOnlyBurst(t *testing.T) {
	original := &rest.Config{Host: "https://example.invalid"}
	c := WithOpeningBurst(original)
	if original.RateLimiter != nil || c.RateLimiter == nil || c.RateLimiter.QPS() != 20 {
		t.Fatal("opening limiter must be a copy at the fixed 20 QPS")
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
