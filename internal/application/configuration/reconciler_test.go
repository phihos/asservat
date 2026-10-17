package configuration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
)

type reconciliationFixture struct {
	mu          sync.Mutex
	snapshot    value.Snapshot
	trust       PermissionTrust
	storeFence  value.PermissionFence
	accepted    []value.PermissionBatch
	suspended   bool
	review      *value.BootstrapReview
	trustCalls  int
	drift       bool
	watchStarts []string
	events      []value.BindingEvent
	finished    chan struct{}
	ids         int
	failAccept  error
}

func (f *reconciliationFixture) PermissionSnapshot(context.Context) (value.Snapshot, error) {
	return f.snapshot, nil
}
func (f *reconciliationFixture) PermissionTrust(context.Context) (PermissionTrust, error) {
	f.trustCalls++
	t := f.trust
	if f.drift && f.trustCalls > 1 {
		t.Digest[0]++
	}
	return t, nil
}
func (f *reconciliationFixture) InitialPermissionReview(context.Context) (value.BootstrapReview, error) {
	if f.review == nil {
		return value.BootstrapReview{}, value.ErrDenied
	}
	return *f.review, nil
}
func (f *reconciliationFixture) BeginPermissions(_ context.Context, root, epoch string, d artifact.Digest) (value.PermissionFence, error) {
	f.storeFence.RootID = root
	f.storeFence.Epoch = epoch
	f.storeFence.TrustDigest = d
	return f.storeFence, nil
}
func (f *reconciliationFixture) RenewPermissions(context.Context, value.PermissionFence) (value.PermissionFence, error) {
	return f.storeFence, nil
}
func (f *reconciliationFixture) AcceptPermissions(_ context.Context, b value.PermissionBatch) (value.PermissionAcceptance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAccept != nil {
		return value.PermissionAcceptance{}, f.failAccept
	}
	if !f.storeFence.Initialized && (b.Initial == nil || !b.Initial.Valid(b.ObservedAt)) {
		return value.PermissionAcceptance{}, value.ErrDenied
	}
	if b.ExpectedSequence != f.storeFence.Sequence {
		return value.PermissionAcceptance{}, value.ErrChanged
	}
	f.accepted = append(f.accepted, cloneBatch(b))
	f.storeFence.Sequence++
	f.storeFence.Initialized = true
	return value.PermissionAcceptance{PermissionFence: f.storeFence, AuditID: b.RequestID}, nil
}
func (f *reconciliationFixture) RefreshPermissions(context.Context, value.PermissionBatch) error {
	return nil
}
func (f *reconciliationFixture) SuspendPermissions(context.Context, value.PermissionFence) error {
	f.suspended = true
	return nil
}
func (f *reconciliationFixture) newID() string {
	f.ids++
	return fmt.Sprintf("11111111-1111-4111-8111-%012d", f.ids)
}
func (f *reconciliationFixture) WatchBindings(_ context.Context, rv string) (BindingWatch, error) {
	f.watchStarts = append(f.watchStarts, rv)
	if len(f.watchStarts) == 1 {
		return &fixtureWatch{empty: true}, nil
	}
	return &fixtureWatch{events: f.events, finished: f.finished}, nil
}

type fixtureWatch struct {
	events   []value.BindingEvent
	empty    bool
	finished chan struct{}
}

func (w *fixtureWatch) Close() {}
func (w *fixtureWatch) Next(ctx context.Context) (value.BindingEvent, error) {
	if w.empty {
		return value.BindingEvent{}, io.EOF
	}
	if len(w.events) > 0 {
		e := w.events[0]
		w.events = w.events[1:]
		return e, nil
	}
	if w.finished != nil {
		close(w.finished)
		w.finished = nil
	}
	<-ctx.Done()
	return value.BindingEvent{}, ctx.Err()
}
func reconciliationTest(t *testing.T) (*reconciliationFixture, BindingReconciler) {
	_, snapshot, fence, now := journalFixture(t)
	f := &reconciliationFixture{snapshot: snapshot, trust: PermissionTrust{Digest: fence.TrustDigest, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, finished: make(chan struct{})}
	f.storeFence.LeaseUntil = now.Add(30 * time.Second)
	f.review = &value.BootstrapReview{Resource: value.Resource{ClusterID: snapshot.ClusterID, Namespace: snapshot.ControlNamespace.Name, NamespaceUID: snapshot.ControlNamespace.UID, Kind: "ConfigMap", UID: "review", ResourceVersion: "rv-review", SpecDigest: artifact.Digest{3}}, Reviewer: "admin", BindingsDigest: InitialBindingDigest(snapshot), ReviewedAt: now, ExpiresAt: now.Add(time.Hour), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	clock := now
	r := BindingReconciler{RootID: journalID, Reader: f, Watcher: f, Trust: f, Review: f, Store: f, Now: func() time.Time { clock = clock.Add(time.Microsecond); return clock }, NewID: f.newID}
	return f, r
}
func TestBindingReconcilerDoesNotTrustPreexistingValuesWithoutReview(t *testing.T) {
	f, r := reconciliationTest(t)
	r.Review = nil
	if err := r.Run(context.Background()); !errors.Is(err, value.ErrDenied) {
		t.Fatal(err)
	}
	if !f.suspended || len(f.accepted) != 0 {
		t.Fatal("unreviewed bootstrap accepted or not suspended")
	}
}
func TestBindingReconcilerRejectsGuardChangeDuringList(t *testing.T) {
	f, r := reconciliationTest(t)
	f.drift = true
	if err := r.Run(context.Background()); !errors.Is(err, value.ErrChanged) {
		t.Fatal(err)
	}
	if !f.suspended || len(f.accepted) != 0 {
		t.Fatal("guard replacement accepted")
	}
}
func TestBindingReconcilerResumesCleanWatchAndCommitsEveryOwner(t *testing.T) {
	f, r := reconciliationTest(t)
	b := cloneBinding(f.snapshot.Bindings[0])
	b.Resource.ResourceVersion = "rv-b"
	b.Resource.Generation++
	b.Resource.SpecDigest[0]++
	b.Subjects[0].ID = "team-b"
	a := cloneBinding(b)
	a.Resource.ResourceVersion = "rv-a"
	a.Resource.Generation++
	a.Resource.SpecDigest[0]++
	a.Subjects[0].ID = "team-a"
	f.events = []value.BindingEvent{{Type: "MODIFIED", ResourceVersion: "rv-b", Binding: &b}, {Type: "MODIFIED", ResourceVersion: "rv-a", Binding: &a}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Wait for the final accepted transaction, not merely event delivery.
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case <-f.finished:
	case <-ctx.Done():
		t.Fatal("watch did not drain")
	}
	deadline := time.NewTimer(100 * time.Millisecond)
	defer deadline.Stop()
	for {
		f.mu.Lock()
		count := len(f.accepted)
		f.mu.Unlock()
		if count == 3 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("last transition not accepted")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(f.watchStarts) != 2 || f.watchStarts[0] != f.watchStarts[1] {
		t.Fatal("clean EOF replaced cursor/epoch")
	}
	if !f.suspended || len(f.accepted) != 3 {
		t.Fatal("missing suspension/transition")
	}
	for i, team := range []string{"team-a", "team-b", "team-a"} {
		if f.accepted[i].Bases[0].Subjects[0].ID != team {
			t.Fatal("ownership coalesced")
		}
		if f.accepted[i].Bases[0].Continuous != (i > 0) {
			t.Fatal("wrong continuity")
		}
	}
	if f.accepted[0].Initial == nil || f.accepted[1].Initial != nil {
		t.Fatal("bootstrap not limited to first acceptance")
	}
}
func TestBindingReconcilerListCannotSkipPendingOwner(t *testing.T) {
	f, r := reconciliationTest(t)
	s := &bindingRun{r: r}
	if err := s.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.snapshot.Bindings[0].Resource.ResourceVersion = "future-rv"
	f.snapshot.ObservedAt = f.snapshot.ObservedAt.Add(time.Microsecond)
	if err := s.refresh(context.Background()); !errors.Is(err, errWatchBehind) {
		t.Fatal(err)
	}
	if len(f.accepted) != 1 || s.journal.Cursor() != f.snapshot.BindingResourceVersion {
		t.Fatal("full list skipped watch history")
	}
}

// The hub-worker logs FixedStep for a stopped epoch; a dropped or renamed
// label would hide where the reconciler stops (ADR-197 runs 23-24).
func TestBindingReconcilerNamesTheStoppingPhase(t *testing.T) {
	for _, c := range []struct {
		name, want string
		setup      func(*reconciliationFixture, *BindingReconciler)
	}{
		{"unreviewed bootstrap", "start", func(_ *reconciliationFixture, r *BindingReconciler) { r.Review = nil }},
		{"guard change during the list", "start/snapshot", func(f *reconciliationFixture, _ *BindingReconciler) { f.drift = true }},
		{"store refuses the batch", "start/accept/store-accept", func(f *reconciliationFixture, _ *BindingReconciler) { f.failAccept = value.ErrUnavailable }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, r := reconciliationTest(t)
			c.setup(f, &r)
			err := r.Run(context.Background())
			var step interface{ FixedStep() string }
			if !errors.As(err, &step) || step.FixedStep() != c.want {
				t.Fatalf("stopped with %v, want step %q", err, c.want)
			}
		})
	}
}
