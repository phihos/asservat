package privacy

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

type policiesFunc func(context.Context) ([]value.ScopedPolicy, error)

func (f policiesFunc) CurrentRetentionPolicies(c context.Context) ([]value.ScopedPolicy, error) {
	return f(c)
}

func testBaseline() value.ScopedPolicy {
	return value.ScopedPolicy{Name: "baseline", Policy: value.Policy{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{1}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300},
		CaseDefaultSeconds: 600, CaseMaximumSeconds: 7200, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 7200, LegalExceptions: "disabled"}
}

func TestRetentionResolverUsesStoredPolicies(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	target := authorization.Target{ClusterID: "11111111-1111-4111-8111-111111111111", NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}
	r := RetentionResolver{Now: func() time.Time { return now }, Policies: policiesFunc(func(context.Context) ([]value.ScopedPolicy, error) {
		return []value.ScopedPolicy{testBaseline()}, nil
	})}
	in := value.Input{Target: target, AnchorAt: now, PrivacyClass: "potentialPersonalData", EvidenceType: "context"}
	got, err := r.Resolve(context.Background(), in)
	if err != nil || got.MaximumSeconds != 86400 || got.RequestedSeconds != 3600 || !got.ValidUntil.Equal(got.ExpiresAt) {
		t.Fatal("evidence resolution", got, err)
	}
	in.EvidenceType = "other"
	got, err = r.ResolveCaseMetadata(context.Background(), in)
	if err != nil || got.MaximumSeconds != 7200 || got.RequestedSeconds != 600 {
		t.Fatal("case metadata did not use case maxima", got, err)
	}
	r.Policies = policiesFunc(func(context.Context) ([]value.ScopedPolicy, error) { return nil, errors.New("down") })
	if _, err = r.Resolve(context.Background(), in); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("unavailable store accepted", err)
	}
	r.Policies = policiesFunc(func(context.Context) ([]value.ScopedPolicy, error) { return nil, nil })
	if _, err = r.Resolve(context.Background(), in); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("collection without baseline", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.Resolve(ctx, in); err == nil {
		t.Fatal("cancelled request accepted")
	}
}
