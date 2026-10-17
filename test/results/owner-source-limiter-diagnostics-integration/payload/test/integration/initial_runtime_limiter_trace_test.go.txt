package integration

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

// Only the owned native fixture supplies this wrapper. Promoted methods retain
// the exact underlying Accept/TryAccept/Stop/QPS behavior; Wait delegates once
// with the original context and returns the identical error without rendering it.
type initialRuntimeNativeLimiter struct {
	flowcontrol.RateLimiter
	trace  *initialRuntimeNativeTrace
	client int
}

var _ flowcontrol.RateLimiter = (*initialRuntimeNativeLimiter)(nil)

func (l *initialRuntimeNativeLimiter) Wait(ctx context.Context) error {
	l.trace.limiterWaits[l.client].Add(1)
	err := l.RateLimiter.Wait(ctx)
	if err != nil {
		// This classifies context state at return, never the provider's cause.
		// A live-context refusal is not by itself proof of predictive throttling.
		if ctx.Err() == nil {
			l.trace.limiterLiveRefusals[l.client].Add(1)
		} else {
			l.trace.limiterCancelledRefusals[l.client].Add(1)
		}
	}
	return err
}

type initialRuntimeNativeLimiterCounts struct {
	waits, liveRefusals, cancelledRefusals [6]int64
}

func (x *initialRuntimeNativeTrace) limiterSnapshot() (out initialRuntimeNativeLimiterCounts) {
	if x == nil {
		return out
	}
	for i := range out.waits {
		out.waits[i] = x.limiterWaits[i].Load()
		out.liveRefusals[i] = x.limiterLiveRefusals[i].Load()
		out.cancelledRefusals[i] = x.limiterCancelledRefusals[i].Load()
	}
	return out
}

func (s initialRuntimeNativeLimiterCounts) subtract(before initialRuntimeNativeLimiterCounts) initialRuntimeNativeLimiterCounts {
	for i := range s.waits {
		s.waits[i] -= before.waits[i]
		s.liveRefusals[i] -= before.liveRefusals[i]
		s.cancelledRefusals[i] -= before.cancelledRefusals[i]
	}
	return s
}

func nativeLimiterConfig() *rest.Config {
	return &rest.Config{Host: "https://synthetic.invalid", ContentConfig: rest.ContentConfig{GroupVersion: &schema.GroupVersion{}, NegotiatedSerializer: scheme.Codecs.WithoutConversion()}}
}

func TestInitialRuntimeLimiterTracePreservesSixOriginalBuckets(t *testing.T) {
	x := newInitialRuntimeNativeTrace(true)
	base := nativeLimiterConfig()
	seen := map[flowcontrol.RateLimiter]bool{}
	for i := range 6 {
		configured := x.config(base, i)
		wrapped, ok := configured.RateLimiter.(*initialRuntimeNativeLimiter)
		if !ok || wrapped.trace != x || wrapped.client != i || wrapped.QPS() != 20 || seen[wrapped.RateLimiter] || base.RateLimiter != nil {
			t.Fatal("original client limiter replaced, aliased or configured incorrectly")
		}
		seen[wrapped.RateLimiter] = true
		copy := rest.CopyConfig(configured)
		if copy.RateLimiter != wrapped {
			t.Fatal("configuration copy replaced the original limiter")
		}
		client, err := rest.UnversionedRESTClientForConfigAndClient(copy, &http.Client{})
		if err != nil || client.GetRateLimiter() != wrapped {
			t.Fatal("REST constructor allocated an additional/default limiter")
		}
		underlying := wrapped.RateLimiter
		x.phase(t, "synthetic-limiter-retention")()
		if client.GetRateLimiter() != wrapped || wrapped.RateLimiter != underlying {
			t.Fatal("phase recreated or replaced the original bucket")
		}
	}
	if x.limiterSnapshot() != (initialRuntimeNativeLimiterCounts{}) {
		t.Fatal("construction or phase observation consumed limiter tokens")
	}
}

func TestInitialRuntimeLimiterTraceRejectsReplacementAndAliasing(t *testing.T) {
	for _, mode := range []string{"nil", "negative", "outside", "configured", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			x := newInitialRuntimeNativeTrace(true)
			config, index := nativeLimiterConfig(), 0
			switch mode {
			case "nil":
				config = nil
			case "negative":
				index = -1
			case "outside":
				index = 6
			case "configured":
				config.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(20, 20)
			case "duplicate":
				x.config(config, index)
			}
			defer func() {
				if recover() == nil {
					t.Error("invalid fixture construction silently changed a limiter")
				}
			}()
			x.config(config, index)
		})
	}
	base := nativeLimiterConfig()
	if newInitialRuntimeNativeTrace(false).config(base, 0) != base || base.RateLimiter != nil {
		t.Fatal("disabled tracing changed original configuration")
	}
}

type nativeLimiterPrivateError struct{}

func (*nativeLimiterPrivateError) Error() string { panic("private limiter error must not be rendered") }

type nativeLimiterDelegationFixture struct {
	wait, accept, try, stop, qps int
	ctx                          context.Context
	err                          error
}

func (f *nativeLimiterDelegationFixture) Wait(ctx context.Context) error {
	f.wait++
	f.ctx = ctx
	return f.err
}
func (f *nativeLimiterDelegationFixture) Accept()         { f.accept++ }
func (f *nativeLimiterDelegationFixture) TryAccept() bool { f.try++; return false }
func (f *nativeLimiterDelegationFixture) Stop()           { f.stop++ }
func (f *nativeLimiterDelegationFixture) QPS() float32    { f.qps++; return 13 }

func TestInitialRuntimeLimiterTraceDelegatesOnceWithoutPrivateText(t *testing.T) {
	x := newInitialRuntimeNativeTrace(true)
	f := &nativeLimiterDelegationFixture{}
	l := &initialRuntimeNativeLimiter{RateLimiter: f, trace: x, client: 3}
	ctx := context.WithValue(context.Background(), struct{ key int }{1}, "original")
	if err := l.Wait(ctx); err != nil || f.wait != 1 || f.ctx != ctx {
		t.Fatal("successful Wait changed original call")
	}
	before := x.limiterSnapshot()
	f.err = &nativeLimiterPrivateError{}
	if err := l.Wait(ctx); err != f.err || f.wait != 2 || f.ctx != ctx || ctx.Err() != nil {
		t.Fatal("live-context refusal changed original context/error")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := l.Wait(cancelled); err != f.err || f.wait != 3 || f.ctx != cancelled {
		t.Fatal("cancelled-context refusal changed original context/error")
	}
	l.Accept()
	if l.TryAccept() || l.QPS() != 13 {
		t.Fatal("passive or blocking method changed its underlying result")
	}
	l.Stop()
	if f.accept != 1 || f.try != 1 || f.stop != 1 || f.qps != 1 {
		t.Fatal("underlying method repeated or omitted")
	}
	want := initialRuntimeNativeLimiterCounts{}
	want.waits[3], want.liveRefusals[3], want.cancelledRefusals[3] = 2, 1, 1
	if x.limiterSnapshot().subtract(before) != want {
		t.Fatal("fixed counters lost exact calls or context-state classification")
	}
}

// Test-only adapter exposes queued reservations in the real pinned x/time
// algorithm, allowing a multi-second backlog without sleepers or tiny deadlines.
// Native installation never uses this adapter, reservations or synthetic load;
// its sole underlying bucket comes from the standard client-go factory above.
type nativeLimiterQueuedFixture struct {
	limiter *rate.Limiter
	waits   int
}

func (f *nativeLimiterQueuedFixture) Wait(ctx context.Context) error {
	f.waits++
	return f.limiter.Wait(ctx)
}
func (f *nativeLimiterQueuedFixture) TryAccept() bool { return f.limiter.Allow() }
func (f *nativeLimiterQueuedFixture) QPS() float32    { return float32(f.limiter.Limit()) }
func (*nativeLimiterQueuedFixture) Stop()             {}
func (f *nativeLimiterQueuedFixture) Accept()         { _ = f.limiter.Wait(context.Background()) }

func TestInitialRuntimeLimiterTracePredictiveRefusalPrecedesHTTP(t *testing.T) {
	x := newInitialRuntimeNativeTrace(true)
	underlying := &nativeLimiterQueuedFixture{limiter: rate.NewLimiter(20, 20)}
	l := &initialRuntimeNativeLimiter{RateLimiter: underlying, trace: x, client: 3}
	config := nativeLimiterConfig()
	config.RateLimiter = l
	var requests atomic.Int32
	client, err := rest.UnversionedRESTClientForConfigAndClient(config, &http.Client{Transport: ownerProbeRoundTripper(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, context.Canceled
	})})
	if err != nil || client.GetRateLimiter() != l {
		t.Fatal("actual REST client lost the selected underlying limiter")
	}
	// Spend the initial burst and queue five seconds of existing reservations.
	// Cancellation below is test cleanup, never native bucket replenishment.
	for range 6 {
		r := underlying.limiter.ReserveN(time.Now(), 20)
		if !r.OK() {
			t.Fatal("synthetic queued reservation rejected")
		}
		defer r.Cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.Get().AbsPath("/synthetic").MaxRetries(0).DoRaw(ctx)
	if err == nil || ctx.Err() != nil || requests.Load() != 0 || underlying.waits != 1 || l.RateLimiter != underlying {
		t.Fatal("real limiter did not refuse one original live-context request before HTTP")
	}
	want := initialRuntimeNativeLimiterCounts{}
	want.waits[3], want.liveRefusals[3] = 1, 1
	if x.limiterSnapshot() != want || client.GetRateLimiter() != l {
		t.Fatal("predictive refusal was missed, reclassified or refilled")
	}
}
