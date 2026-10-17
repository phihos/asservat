package privacy

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/privacy"
)

type retentionFunc func(context.Context, authorization.Target) (value.PolicySet, error)

func (f retentionFunc) RetentionPolicies(c context.Context, t authorization.Target) (value.PolicySet, error) {
	return f(c, t)
}
func TestRetentionReaderCannotFreshenAfterIO(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	target := authorization.Target{ClusterID: "11111111-1111-4111-8111-111111111111", NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}
	r := RetentionResolver{Now: func() time.Time { return now }, Policies: retentionFunc(func(ctx context.Context, got authorization.Target) (value.PolicySet, error) {
		if got != target {
			t.Fatal("substituted target")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded call")
		}
		old := now
		now = now.Add(time.Minute)
		return value.PolicySet{Target: target, Complete: true, ObservedAt: old, FreshUntil: old.Add(30 * time.Second)}, nil
	})}
	if _, err := r.Resolve(context.Background(), value.Input{Target: target, AnchorAt: now, PrivacyClass: "potentialPersonalData", EvidenceType: "context"}); err == nil {
		t.Fatal("stale policy accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Policies = retentionFunc(func(context.Context, authorization.Target) (value.PolicySet, error) {
		t.Fatal("called on cancelled request")
		return value.PolicySet{}, nil
	})
	if _, err := r.Resolve(ctx, value.Input{Target: target}); err == nil {
		t.Fatal("cancelled request accepted")
	}
}
