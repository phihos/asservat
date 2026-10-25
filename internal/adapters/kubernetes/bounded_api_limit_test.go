package kubernetes

import (
	"testing"

	"k8s.io/client-go/rest"
)

// The bounded client keeps its fixed 20/20 budget unless the caller asks for
// exactly the ADR-208 opening budget.
func TestBoundedAPIRateLimit(t *testing.T) {
	for _, tc := range []struct {
		qps   float32
		burst int
		want  float32
	}{{0, 0, 20}, {200, 400, 20}, {OpeningQPS, 400, 20}, {OpeningQPS, OpeningBurst, OpeningQPS}} {
		api, err := newBoundedAPI(&rest.Config{Host: "https://kubernetes.example.test", QPS: tc.qps, Burst: tc.burst})
		if err != nil {
			t.Fatal(err)
		}
		if got := api.GetRateLimiter().QPS(); got != tc.want {
			t.Fatal(tc.qps, tc.burst, got, tc.want)
		}
	}
}
