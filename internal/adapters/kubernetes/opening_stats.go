package kubernetes

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"k8s.io/client-go/util/flowcontrol"
)

// openingStats counts the process's opening-client Kubernetes traffic for a
// diagnostic summary: request round trips and ADR-208 limiter waits. It holds
// no identifiers, paths or bodies.
var openingStats struct {
	requests, slow1, slow2, failed       atomic.Int64
	waits, refused, waitNanos, maxWaitNs atomic.Int64
}

type measuredLimiter struct{ flowcontrol.RateLimiter }

func (m measuredLimiter) Wait(ctx context.Context) error {
	start := time.Now()
	err := m.RateLimiter.Wait(ctx)
	d := time.Since(start)
	if err != nil {
		openingStats.refused.Add(1)
	}
	if d >= 100*time.Millisecond {
		openingStats.waits.Add(1)
		openingStats.waitNanos.Add(int64(d))
		for {
			old := openingStats.maxWaitNs.Load()
			if int64(d) <= old || openingStats.maxWaitNs.CompareAndSwap(old, int64(d)) {
				break
			}
		}
	}
	return err
}

type measuredTransport struct{ next http.RoundTripper }

func (m measuredTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := m.next.RoundTrip(r)
	d := time.Since(start)
	openingStats.requests.Add(1)
	if err != nil {
		openingStats.failed.Add(1)
	}
	if d >= time.Second {
		openingStats.slow1.Add(1)
	}
	if d >= 2*time.Second {
		openingStats.slow2.Add(1)
	}
	return resp, err
}

// OpeningStatsLine summarizes the counters since the last call and resets
// them; it returns "" without traffic.
func OpeningStatsLine() string {
	n := openingStats.requests.Swap(0)
	waits := openingStats.waits.Swap(0)
	if n == 0 && waits == 0 {
		return ""
	}
	slow1, slow2, failed := openingStats.slow1.Swap(0), openingStats.slow2.Swap(0), openingStats.failed.Swap(0)
	refused, total, max := openingStats.refused.Swap(0), openingStats.waitNanos.Swap(0), openingStats.maxWaitNs.Swap(0)
	return fmt.Sprintf("requests=%d failed=%d slow>=1s=%d slow>=2s=%d limiter-waits>=100ms=%d wait-total=%s wait-max=%s limiter-refused=%d",
		n, failed, slow1, slow2, waits, time.Duration(total).Round(10*time.Millisecond), time.Duration(max).Round(10*time.Millisecond), refused)
}
