package integration

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

// Upstream provider administration belongs to the owned fixture. The original
// product bootstrap and all subsequent native/SQL effects remain real; neither
// these provider credentials nor the fixture administrator enter runtime pods.
type initialRuntimeNativeProviders struct {
	trace                 *initialRuntimeNativeTrace
	issuerRoots           [][]byte
	installation, cluster string
	worker                contracts.ConfigurationProviderSelection
	owner                 contracts.OwnerProviderSelection
	client                *http.Client
	endpoint              string
	fixture               fixture
	desired               contracts.InitialBootstrap
}

// These counters wrap the original six clients once at construction. Exactly
// one standard 20/20 limiter is supplied per client, preventing the REST factory
// from creating a second default bucket. No phase replaces or refills it.
type initialRuntimeNativeTrace struct {
	calls                    [6]atomic.Int64
	ownerDeadlines           nativeOwnerDeadlineTrace
	limiterCreated           [6]atomic.Bool
	limiterWaits             [6]atomic.Int64
	limiterLiveRefusals      [6]atomic.Int64
	limiterCancelledRefusals [6]atomic.Int64
}

func newInitialRuntimeNativeTrace(enabled bool) *initialRuntimeNativeTrace {
	if !enabled {
		return nil
	}
	return &initialRuntimeNativeTrace{}
}
func (x *initialRuntimeNativeTrace) config(original *rest.Config, i int) *rest.Config {
	if x == nil {
		return original
	}
	if original == nil || i < 0 || i >= len(x.calls) || original.RateLimiter != nil || !x.limiterCreated[i].CompareAndSwap(false, true) {
		panic("native limiter trace requires one unconfigured original client per index")
	}
	copy := rest.CopyConfig(original)
	// newBoundedAPI keeps this exact pointer; client-go creates a default only
	// for nil RateLimiter. Allocation happens once before any token is consumed.
	copy.RateLimiter = &initialRuntimeNativeLimiter{RateLimiter: flowcontrol.NewTokenBucketRateLimiter(20, 20), trace: x, client: i}
	copy.Wrap(func(next http.RoundTripper) http.RoundTripper {
		return ownerProbeRoundTripper(func(r *http.Request) (*http.Response, error) {
			x.calls[i].Add(1)
			done := x.ownerDeadlines.request(i, r.Context())
			defer done()
			return next.RoundTrip(r)
		})
	})
	return copy
}
func (x *initialRuntimeNativeTrace) phase(t *testing.T, name string) func() {
	if x == nil {
		return func() {}
	}
	start := time.Now()
	deadlineSummary := x.ownerDeadlines.begin(name)
	limiterBefore := x.limiterSnapshot()
	before := [6]int64{}
	for i := range before {
		before[i] = x.calls[i].Load()
	}
	return func() {
		var used [6]int64
		for i := range used {
			used[i] = x.calls[i].Load() - before[i]
		}
		limiter := x.limiterSnapshot().subtract(limiterBefore)
		t.Logf("native phase=%s elapsed=%s calls[C B H S W T]=%v waits=%v wait-refusals-live-context=%v wait-refusals-cancelled-context=%v original 20QPS/burst20 clients retained", name, time.Since(start), used, limiter.waits, limiter.liveRefusals, limiter.cancelledRefusals)
		deadlineSummary(t)
	}
}
