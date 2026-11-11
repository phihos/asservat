package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"errors"
	"reflect"
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

type lifecyclePublicationFixture struct {
	decision             value.LifecycleDecision
	batch                []value.LifecycleDecision
	found                bool
	selectErr, writeErr  error
	ackErr               error
	single, batches      int
	writes, acknowledged []value.LifecycleDecision
}

func (f *lifecyclePublicationFixture) PendingLifecycleDecision(context.Context) (value.LifecycleDecision, bool, error) {
	f.single++
	return f.decision, f.found, f.selectErr
}

func (f *lifecyclePublicationFixture) PendingLifecycleDecisions(context.Context) ([]value.LifecycleDecision, error) {
	f.batches++
	return f.batch, nil
}

func (f *lifecyclePublicationFixture) WriteLifecycleDecision(_ context.Context, d value.LifecycleDecision) (audit.Receipt, error) {
	f.writes = append(f.writes, d)
	return audit.Receipt{Key: audit.LifecycleKey(d.RootID, d.ID), Version: "version", ETag: "etag", Bytes: 1, SHA256: artifact.Digest{1}}, f.writeErr
}

func (f *lifecyclePublicationFixture) AcknowledgeLifecycleDecision(_ context.Context, d value.LifecycleDecision, r audit.Receipt) error {
	if !r.ValidLifecycle(d.RootID, d.ID) {
		return artifact.ErrInvalid
	}
	f.acknowledged = append(f.acknowledged, d)
	return f.ackErr
}

func TestLifecyclePublisherPublishOne(t *testing.T) {
	d := lifecyclePublicationDecision(t)
	failure := errors.New("fixture publication unavailable")
	for _, tc := range []struct {
		name                 string
		decision             value.LifecycleDecision
		found                bool
		selectErr, writeErr  error
		ackErr, wantErr      error
		writes, acknowledges int
	}{
		{name: "empty"},
		{name: "selection failed", selectErr: failure, wantErr: failure},
		{name: "selected row failed to decode", found: true, selectErr: failure, wantErr: failure},
		{name: "invalid decision", found: true, wantErr: ErrUnavailable},
		{name: "provider failed", decision: d, found: true, writeErr: failure, wantErr: failure, writes: 1},
		{name: "acknowledgement failed", decision: d, found: true, ackErr: failure, wantErr: failure, writes: 1, acknowledges: 1},
		{name: "published", decision: d, found: true, writes: 1, acknowledges: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &lifecyclePublicationFixture{decision: tc.decision, found: tc.found, selectErr: tc.selectErr, writeErr: tc.writeErr, ackErr: tc.ackErr}
			p := LifecyclePublisher{Ledger: f, Objects: f}
			attempted, err := p.PublishOne(t.Context())
			if attempted != tc.found || !errors.Is(err, tc.wantErr) || f.single != 1 || f.batches != 0 || len(f.writes) != tc.writes || len(f.acknowledged) != tc.acknowledges {
				t.Fatalf("attempted=%t err=%v selections=%d batches=%d writes=%d acknowledgements=%d", attempted, err, f.single, f.batches, len(f.writes), len(f.acknowledged))
			}
			if tc.writes > 0 && !reflect.DeepEqual(f.writes[0], d) || tc.acknowledges > 0 && !reflect.DeepEqual(f.acknowledged[0], d) {
				t.Fatal("publication changed the selected decision")
			}
		})
	}
}

func TestLifecyclePublisherKeepsBatchBound(t *testing.T) {
	d := lifecyclePublicationDecision(t)
	f := &lifecyclePublicationFixture{batch: make([]value.LifecycleDecision, 65)}
	for i := range f.batch {
		f.batch[i] = d
	}
	p := LifecyclePublisher{Ledger: f, Objects: f}
	if err := p.Publish(t.Context()); !errors.Is(err, ErrUnavailable) || len(f.writes) != 0 {
		t.Fatal("oversized pending batch reached publication", err)
	}
	f.batch = f.batch[:64]
	if err := p.Publish(t.Context()); err != nil || f.batches != 2 || f.single != 0 || len(f.writes) != 64 || len(f.acknowledged) != 64 {
		t.Fatal("batch publication changed its existing bound", err)
	}
}

func lifecyclePublicationDecision(t *testing.T) value.LifecycleDecision {
	t.Helper()
	id := "11111111-1111-4111-8111-111111111111"
	anchor := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	policies := []artifact.RetentionRule{{UID: "base", Generation: 1, Digest: artifact.Digest{1}}}
	d := value.LifecycleDecision{
		ID: id, RootID: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id},
		Target: authorization.Target{ClusterID: id, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}, Sequence: 1,
		RegistrationDigest: artifact.Digest{1}, PolicyRevision: identity.Revision{UID: "set", Generation: 1, Digest: artifact.Digest{2}},
		Policies: policies, Origins: policies, Previous: value.Deadlines{AnchorAt: anchor, ExpiresAt: anchor.Add(2 * time.Hour), DeleteBy: anchor.Add(3 * time.Hour)},
		Effective:  value.Deadlines{AnchorAt: anchor, ExpiresAt: anchor.Add(time.Hour), DeleteBy: anchor.Add(2 * time.Hour)},
		ObservedAt: anchor.Add(time.Second), ValidUntil: anchor.Add(2 * time.Second),
	}
	if !d.Valid() {
		t.Fatal("invalid lifecycle publication fixture")
	}
	return d
}
