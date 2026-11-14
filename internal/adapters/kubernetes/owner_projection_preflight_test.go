package kubernetes

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"k8s.io/client-go/rest"
)

// These tests retain the existing synthetic SQL/provider/API fixture boundary.
// Compatibility wrappers execute the selected split protocol. Counts describe
// actual requests through its original six clients, not native
// API admission, real row contention or drained-bucket availability.
type projectionSplitRoundTripper func(*http.Request) (*http.Response, error)

func (f projectionSplitRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type projectionSplitCounters struct{ calls [6]atomic.Int32 }

func (c *projectionSplitCounters) snapshot() (out [6]int32) {
	for i := range out {
		out[i] = c.calls[i].Load()
	}
	return out
}
func projectionSplitClients(f *ownerProjectionOperationFixture) [6]rest.Interface {
	p := f.resources.preparer
	return [6]rest.Interface{p.creator.api, p.protection.observer.api, p.protection.probe.api, f.source.client.api, f.source.protection.probe.api, f.source.fleet.protection.probe.api}
}
func projectionSplitCount(t *testing.T, f *ownerProjectionOperationFixture) *projectionSplitCounters {
	t.Helper()
	out := &projectionSplitCounters{}
	seen := map[*http.Client]bool{}
	for i, api := range projectionSplitClients(f) {
		client, ok := api.(*rest.RESTClient)
		if !ok || client.Client == nil || seen[client.Client] {
			t.Fatal("fixture did not retain six distinct HTTP clients")
		}
		seen[client.Client] = true
		before, limiter := client.Client.Transport, client.GetRateLimiter()
		client.Client.Transport = projectionSplitRoundTripper(func(r *http.Request) (*http.Response, error) { out.calls[i].Add(1); return before.RoundTrip(r) })
		t.Cleanup(func() {
			if client.GetRateLimiter() != limiter {
				t.Error("original limiter replaced")
			}
			client.Client.Transport = before
		})
	}
	return out
}
func projectionSplitDifference(after, before [6]int32) [6]int32 {
	for i := range after {
		after[i] -= before[i]
	}
	return after
}

func projectionSplitNoParentEffect(t *testing.T, f *ownerProjectionOperationFixture) {
	t.Helper()
	p := f.projection.projection
	if p.attemptedParent || p.attemptedCredentials || p.attemptedConfiguration || p.attemptedLaunch || f.journalWrites.Load() != 0 || f.verification.checks != 0 || f.creates[0].Load() != 0 || f.creates[1].Load() != 0 || f.launches.Load() != 0 {
		t.Fatal("failed first admission reached attempt or effect")
	}
}

type projectionSplitVerifier struct {
	advance func(context.Context, *OwnerProjectionOperation) (OwnerProjectionAdvance, error)
	final   OwnerProjectionFinalizationVerification
}

func (f projectionSplitVerifier) AdvanceOwnerProjectionOperation(ctx context.Context, op *OwnerProjectionOperation) (OwnerProjectionAdvance, error) {
	return f.advance(ctx, op)
}

func (f projectionSplitVerifier) FinalizeOwnerProjectionOperation(ctx context.Context, op *OwnerProjectionFinalization) (OwnerProjectionAdvance, error) {
	return f.final.FinalizeOwnerProjectionOperation(ctx, op)
}
