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
