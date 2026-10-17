package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"errors"
	"testing"
	"time"
)

type retainedFixture struct {
	r     value.RetainedArtifact
	set   value.PolicySet
	saved []value.LifecycleDecision
	fail  bool
}

func (f *retainedFixture) RetainedArtifact(context.Context, artifact.Location) (value.RetainedArtifact, error) {
	return f.r, nil
}
func (f *retainedFixture) TightenRetention(_ context.Context, d value.LifecycleDecision) error {
	f.saved = append(f.saved, d)
	return nil
}
func (f *retainedFixture) RetentionPolicies(context.Context, authorization.Target) (value.PolicySet, error) {
	if f.fail {
		return value.PolicySet{}, errors.New("unavailable")
	}
	return f.set, nil
}
func TestShortenerKeepsOriginalAnchorRequestAndOverdueObligation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "11111111-1111-4111-8111-111111111111"
	anchor := now.Add(-3 * time.Hour)
	target := authorization.Target{ClusterID: id, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}
	reg := artifact.Registration{Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, StoreID: id, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: anchor, WriteUntil: anchor.Add(time.Minute), ExpiresAt: anchor.Add(5 * time.Hour), DeleteBy: anchor.Add(6 * time.Hour)}
	f := &retainedFixture{r: value.RetainedArtifact{RootID: id, Registration: reg, OriginPolicies: []artifact.RetentionRule{{UID: "base", Generation: 1, Digest: artifact.Digest{3}}}, Input: value.Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "context", AnchorAt: anchor, RequestedSeconds: 18000}, Effective: value.Deadlines{AnchorAt: anchor, ExpiresAt: reg.ExpiresAt, DeleteBy: reg.DeleteBy}}, set: value.PolicySet{Target: target, Revision: identity.Revision{UID: "set", Generation: 1, Digest: [32]byte{1}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Complete: true, Policies: []value.Policy{{Revision: identity.Revision{UID: "base", Generation: 2, Digest: [32]byte{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 7200, DeletionBudgetSeconds: 300}}}}
	s := RetentionShortener{Ledger: f, Resolver: RetentionResolver{Policies: f, RetainedPolicies: f, Now: func() time.Time { return now }}, Now: func() time.Time { return now }, NewID: func() string { return id }}
	if err := s.Reconcile(context.Background(), reg.Location); err != nil {
		t.Fatal(err)
	}
	if len(f.saved) != 1 || !f.saved[0].Valid() || !f.saved[0].Effective.DeleteBy.Equal(anchor.Add(2*time.Hour)) || !f.saved[0].Effective.DeleteBy.Before(now) || f.saved[0].RegistrationDigest != RegistrationDigest(reg) {
		t.Fatal("lost overdue policy", f.saved)
	}
	f.r.Effective = f.saved[0].Effective
	f.r.Sequence = 1
	f.set.Policies[0].MaximumSeconds = 86400
	if err := s.Reconcile(context.Background(), reg.Location); err != nil || len(f.saved) != 1 {
		t.Fatal("policy relaxation created a renewal", err)
	}
	f.fail = true
	if err := s.Reconcile(context.Background(), reg.Location); err == nil || len(f.saved) != 1 {
		t.Fatal("missing policy accepted")
	}
}

func (f *retainedFixture) RetainedRetentionPolicies(ctx context.Context, t authorization.Target, origins []artifact.RetentionRule) (value.PolicySet, error) {
	if len(origins) != 1 || origins[0].UID != "base" {
		return value.PolicySet{}, value.ErrInvalid
	}
	return f.RetentionPolicies(ctx, t)
}
