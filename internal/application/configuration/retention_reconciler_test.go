package configuration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
)

type retentionReconcileFixture struct {
	now                               time.Time
	list                              PolicyList
	review                            *value.RetentionBootstrapReview
	source                            privacy.PolicySourceRef
	fence                             RetentionFence
	previous                          *RetentionCheckpoint
	accepted                          []RetentionCheckpoint
	savedCursors                      []string
	starts                            []string
	events                            []PolicyEvent
	listReads, guards, ids, failGuard int
	firstEOF                          bool
	watchErr                          error
	suspended                         bool
	done                              chan struct{}
	want                              int
	once                              sync.Once
}

func (f *retentionReconcileFixture) RetentionPolicyList(context.Context) (PolicyList, error) {
	f.listReads++
	f.now = f.now.Add(time.Microsecond)
	list := clonePolicyList(f.list)
	list.Snapshot.ObservedAt = f.now
	list.Snapshot.FreshUntil = f.now.Add(5 * time.Second)
	return list, nil
}
func (f *retentionReconcileFixture) RetentionProtection(context.Context) (privacy.SourceProtection, error) {
	f.guards++
	p := privacy.SourceProtection{SourceClusterID: f.source.ClusterID, ControlNamespaceUID: f.source.ControlNamespaceUID, Digest: f.source.ProtectionDigest, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}
	if f.guards == f.failGuard {
		p.Digest[0]++
	}
	return p, nil
}
func (f *retentionReconcileFixture) InitialRetentionReview(context.Context) (value.RetentionBootstrapReview, error) {
	if f.review == nil {
		return value.RetentionBootstrapReview{}, value.ErrDenied
	}
	return *f.review, nil
}
func (f *retentionReconcileFixture) BeginRetention(_ context.Context, root string, source privacy.PolicySourceRef, epoch string) (RetentionStart, error) {
	f.fence = RetentionFence{RootID: root, Source: source, Epoch: epoch, LeaseUntil: f.now.Add(30 * time.Second)}
	if f.previous != nil {
		f.fence.Sequence = f.previous.Record.Sequence
	}
	cursor := ""
	if f.previous != nil {
		cursor = f.previous.Transition.List.ResourceVersion
	}
	if len(f.savedCursors) > 0 {
		cursor = f.savedCursors[len(f.savedCursors)-1]
	}
	return RetentionStart{Fence: f.fence, Checkpoint: f.previous, ResumeCursor: cursor}, nil
}
func (f *retentionReconcileFixture) AcceptRetention(_ context.Context, t RetentionTransition) (RetentionCheckpoint, error) {
	if t.Fence.Sequence != f.fence.Sequence {
		return RetentionCheckpoint{}, value.ErrChanged
	}
	r, err := ValidateRetentionTransition(t, f.previous, f.now)
	if err != nil {
		return RetentionCheckpoint{}, err
	}
	c := RetentionCheckpoint{Transition: t, Record: r}
	f.previous = &c
	f.fence.Sequence++
	f.accepted = append(f.accepted, c)
	if len(f.accepted)+len(f.savedCursors) == f.want {
		f.once.Do(func() { close(f.done) })
	}
	return c, nil
}
func (f *retentionReconcileFixture) RenewRetention(_ context.Context, prior RetentionFence) (RetentionFence, error) {
	f.fence.LeaseUntil = f.now.Add(30 * time.Second)
	return f.fence, nil
}
func (f *retentionReconcileFixture) AdvanceRetentionCursor(_ context.Context, prior RetentionFence, cursor string) error {
	if prior.Sequence != f.fence.Sequence {
		return value.ErrChanged
	}
	f.savedCursors = append(f.savedCursors, cursor)
	if len(f.accepted)+len(f.savedCursors) == f.want {
		f.once.Do(func() { close(f.done) })
	}
	return nil
}
func (f *retentionReconcileFixture) ObserveRetention(_ context.Context, o RetentionObservation) error {
	if f.previous == nil {
		return value.ErrChanged
	}
	j, err := ResumeRetentionJournal(f.previous.Transition.List)
	if err != nil {
		return err
	}
	if err = j.Confirm(o.List, f.now); err != nil {
		return value.ErrRetentionHistoryBehind
	}
	return nil
}
func (f *retentionReconcileFixture) SuspendRetention(context.Context, RetentionFence) error {
	f.suspended = true
	return nil
}
func (f *retentionReconcileFixture) newID() string {
	f.ids++
	return fmt.Sprintf("22222222-2222-4222-8222-%012d", f.ids)
}
func (f *retentionReconcileFixture) WatchRetentionPolicies(_ context.Context, rv string) (RetentionWatch, error) {
	f.starts = append(f.starts, rv)
	if f.watchErr != nil {
		return nil, f.watchErr
	}
	if f.firstEOF && len(f.starts) == 1 {
		return &retentionFixtureWatch{eof: true}, nil
	}
	events := f.events
	f.events = nil
	return &retentionFixtureWatch{events: events}, nil
}

type retentionFixtureWatch struct {
	events []PolicyEvent
	eof    bool
}

func (w *retentionFixtureWatch) Close() {}
func (w *retentionFixtureWatch) Next(ctx context.Context) (PolicyEvent, error) {
	if w.eof {
		return PolicyEvent{}, io.EOF
	}
	if len(w.events) > 0 {
		e := w.events[0]
		w.events = w.events[1:]
		return e, nil
	}
	<-ctx.Done()
	return PolicyEvent{}, ctx.Err()
}
func retentionReconciliation(t *testing.T) (*retentionReconcileFixture, RetentionReconciler) {
	t.Helper()
	x, _ := retentionTransitionFixture(t)
	f := &retentionReconcileFixture{now: x.List.Snapshot.ObservedAt, list: x.List, review: x.Review, source: x.Fence.Source, done: make(chan struct{})}
	r := RetentionReconciler{RootID: x.Fence.RootID, Source: f.source, Reader: f, Watcher: f, Protection: f, Review: f, Store: f, Now: func() time.Time { return f.now }, NewID: f.newID}
	return f, r
}
func TestRetentionReconcilerRequiresInitialValuesAndStableGuard(t *testing.T) {
	for _, mode := range []string{"review", "guard", "source"} {
		t.Run(mode, func(t *testing.T) {
			f, r := retentionReconciliation(t)
			switch mode {
			case "review":
				r.Review = nil
			case "guard":
				f.failGuard = 2
			case "source":
				f.list.Snapshot.Hub = false
			}
			if err := r.Run(context.Background()); err == nil {
				t.Fatal("invalid source accepted")
			}
			if !f.suspended || len(f.accepted) != 0 {
				t.Fatal("failed bootstrap left a live source")
			}
		})
	}
}
func TestRetentionReconcilerResumesDurableExpiredCursorWithoutReplacingHistory(t *testing.T) {
	f, r := retentionReconciliation(t)
	x, previous := retentionTransitionFixture(t)
	f.previous = &previous
	f.list = clonePolicyList(x.List)
	f.source = x.Fence.Source
	r.Source = f.source
	f.now = x.List.Snapshot.ObservedAt.Add(time.Hour)
	f.firstEOF = true
	f.want = 3
	lower := clonePolicy(x.List.Snapshot.Policies[0])
	lower.Policy.MaximumSeconds = 600
	lower.Policy.Revision.Generation++
	lower.Policy.Revision.Digest[0]++
	raised := clonePolicy(lower)
	raised.Policy.MaximumSeconds = 7200
	raised.Policy.Revision.Generation++
	raised.Policy.Revision.Digest[0]++
	f.list.Snapshot.Policies[0] = raised
	f.list.Snapshot.Revision.Digest = RetentionSnapshotDigest(f.list.Snapshot)
	f.list.ResourceVersion = "raised:3"
	f.list.Versions[raised.Policy.Revision.UID] = "raised:3"
	f.events = []PolicyEvent{{Type: "MODIFIED", ResourceVersion: "lower:2", Policy: &lower}, {Type: "MODIFIED", ResourceVersion: "raised:3", Policy: &raised}, {Type: "BOOKMARK", ResourceVersion: "bookmark:4"}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case <-f.done:
		cancel()
	case <-ctx.Done():
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !f.suspended || f.listReads != 1 || len(f.accepted) != 2 || len(f.starts) != 2 || f.starts[0] != x.List.ResourceVersion || f.starts[1] != x.List.ResourceVersion {
		t.Fatal("resume skipped history", f.listReads, len(f.accepted), f.starts)
	}
	if f.accepted[0].Transition.List.Snapshot.Policies[0].Policy.MaximumSeconds != 600 || f.accepted[1].Transition.List.Snapshot.Policies[0].Policy.MaximumSeconds != 7200 || len(f.savedCursors) != 1 || f.savedCursors[0] != "bookmark:4" {
		t.Fatal("source transitions coalesced")
	}
	for _, a := range f.accepted {
		if !a.Transition.List.Snapshot.ObservedAt.Equal(x.List.Snapshot.ObservedAt) || !a.Transition.List.Snapshot.FreshUntil.Equal(x.List.Snapshot.FreshUntil) {
			t.Fatal("replay/bookmark renewed source authority")
		}
	}
}
func TestRetentionReconcilerHistoryFailureCannotResetToList(t *testing.T) {
	f, r := retentionReconciliation(t)
	_, p := retentionTransitionFixture(t)
	f.previous = &p
	f.watchErr = value.ErrChanged
	if err := r.Run(context.Background()); !errors.Is(err, value.ErrChanged) {
		t.Fatal(err)
	}
	if f.listReads != 1 || len(f.accepted) != 0 || !f.suspended {
		t.Fatal("watch history failure relisted or kept renewing")
	}
}
func TestRetentionReconcilerGuardLossStopsBeforeNextCommit(t *testing.T) {
	f, r := retentionReconciliation(t)
	_, p := retentionTransitionFixture(t)
	f.previous = &p
	f.failGuard = 4
	f.events = []PolicyEvent{{Type: "BOOKMARK", ResourceVersion: "bookmark:2"}}
	if err := r.Run(context.Background()); !errors.Is(err, value.ErrChanged) {
		t.Fatal(err)
	}
	if len(f.accepted) != 0 || !f.suspended {
		t.Fatal("lost guard persisted a new acceptance")
	}
}

type jitteredRetentionProtection struct{ fixture *retentionReconcileFixture }

func (g jitteredRetentionProtection) RetentionProtection(ctx context.Context) (privacy.SourceProtection, error) {
	p, err := g.fixture.RetentionProtection(ctx)
	// Two bootstrap checks precede the first maintenance check. A small
	// variation in that check must not cost an entire subsequent timer cycle.
	if g.fixture.guards == 3 {
		select {
		case <-time.After(120 * time.Millisecond):
		case <-ctx.Done():
			return privacy.SourceProtection{}, ctx.Err()
		}
	}
	return p, err
}

type timedRetentionReader struct {
	fixture *retentionReconcileFixture
	reads   chan time.Time
}

func (r timedRetentionReader) RetentionPolicyList(ctx context.Context) (PolicyList, error) {
	r.reads <- time.Now()
	return r.fixture.RetentionPolicyList(ctx)
}

func TestRetentionRenewalDoesNotSkipCycleAfterGuardTimingShift(t *testing.T) {
	f, r := retentionReconciliation(t)
	origin, wall := f.now, time.Now()
	r.Now = func() time.Time {
		f.now = origin.Add(time.Since(wall))
		return f.now
	}
	reads := make(chan time.Time, 8)
	r.Reader = timedRetentionReader{f, reads}
	r.Protection = jitteredRetentionProtection{f}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	var observed []time.Time
	for len(observed) < 3 {
		select {
		case at := <-reads:
			observed = append(observed, at)
		case err := <-done:
			t.Fatal("reconciler ended before renewal", err)
		case <-ctx.Done():
			<-done
			t.Fatal("no timely renewal", observed)
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// First read is bootstrap; compare the two complete observations. Keep
	// scheduling tolerance, but reject the previous nearly two-second gap.
	if gap := observed[2].Sub(observed[1]); gap < time.Second || gap > 1500*time.Millisecond {
		t.Fatal("observation renewal skipped a cycle or exceeded its rate", gap)
	}
}
