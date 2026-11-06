package configuration

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
)

type restartPermissionStore struct {
	*reconciliationFixture
	refreshErr      error
	begun           []value.PermissionFence
	snapshots       int
	joined          *atomic.Bool
	suspendUnjoined bool
}

func (s *restartPermissionStore) BeginPermissions(ctx context.Context, root, epoch string, digest artifact.Digest) (value.PermissionFence, error) {
	// Match the existing SQL reset: a new epoch retains initialization, but
	// does not inherit the prior journal's sequence or accepted observations.
	if len(s.begun) > 0 && !s.suspended {
		panic("successor began before previous epoch suspension")
	}
	s.suspended = false
	s.storeFence.Sequence = 0
	fence, err := s.reconciliationFixture.BeginPermissions(ctx, root, epoch, digest)
	s.begun = append(s.begun, fence)
	return fence, err
}
func (s *restartPermissionStore) PermissionSnapshot(ctx context.Context) (value.Snapshot, error) {
	s.snapshots++
	// Each controlled complete LIST is a new observation of the same object
	// versions; a fixed timestamp would correctly wait for watch catch-up.
	s.snapshot.ObservedAt = s.snapshot.ObservedAt.Add(time.Microsecond)
	return s.reconciliationFixture.PermissionSnapshot(ctx)
}
func (s *restartPermissionStore) RefreshPermissions(context.Context, value.PermissionBatch) error {
	return s.refreshErr
}
func (s *restartPermissionStore) SuspendPermissions(ctx context.Context, fence value.PermissionFence) error {
	if len(s.begun) == 0 || fence.Epoch != s.begun[len(s.begun)-1].Epoch {
		panic("suspension replaced the owned epoch")
	}
	if s.joined != nil && !s.joined.Load() {
		s.suspendUnjoined = true
	}
	return s.reconciliationFixture.SuspendPermissions(ctx, fence)
}

type restartJoinedWatch struct {
	closing, release chan struct{}
	joined           atomic.Bool
}

func (*restartJoinedWatch) Next(context.Context) (value.BindingEvent, error) {
	return value.BindingEvent{}, value.ErrUnavailable
}
func (w *restartJoinedWatch) Close() {
	close(w.closing)
	<-w.release
	w.joined.Store(true)
}

type restartOneWatch struct{ watch *restartJoinedWatch }

func (w restartOneWatch) WatchBindings(context.Context, string) (BindingWatch, error) {
	return w.watch, nil
}

func TestPermissionEpochResultWaitsForOriginalWatchJoin(t *testing.T) {
	f, r := reconciliationTest(t)
	w := &restartJoinedWatch{closing: make(chan struct{}), release: make(chan struct{})}
	store := &restartPermissionStore{reconciliationFixture: f, joined: &w.joined}
	r.Store, r.Reader, r.Watcher = store, store, restartOneWatch{w}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan PermissionEpochResult, 1)
	go func() { done <- r.RunEpoch(ctx) }()
	select {
	case <-w.closing:
	case result := <-done:
		t.Fatal("run ended before reaching original watch join", result)
	case <-ctx.Done():
		t.Fatal("original watch did not reach close")
	}
	select {
	case <-done:
		t.Fatal("scheduling fact escaped before original watch joined")
	default:
	}
	close(w.release)
	result := <-done
	if !result.Suspended || !errors.Is(result.Err, value.ErrUnavailable) || !w.joined.Load() || store.suspendUnjoined || !f.suspended {
		t.Fatal("completed owned epoch missing positive joined suspension", result, store.suspendUnjoined)
	}
}

// A failed refresh abandons its pending journal. Only a new guard/full LIST
// and new epoch can restore observation; changed source versions do not gain
// continuity or an old audience merely because restart scheduling is shorter.
func TestPermissionEpochRestartRebuildsGuardListAndJournal(t *testing.T) {
	f, r := reconciliationTest(t)
	store := &restartPermissionStore{reconciliationFixture: f, refreshErr: value.ErrUnavailable}
	r.Store, r.Reader = store, store
	firstCtx, stopFirst := context.WithTimeout(t.Context(), 3*time.Second)
	defer stopFirst()
	first := r.RunEpoch(firstCtx) // Existing one-second tick reaches refresh.
	if !first.Suspended || !errors.Is(first.Err, value.ErrUnavailable) || len(f.accepted) != 1 || len(store.begun) != 1 {
		t.Fatal("failed original refresh did not close its epoch", first)
	}
	beforeSnapshots, beforeTrust := store.snapshots, f.trustCalls
	clock := f.snapshot.ObservedAt.Add(2 * time.Second)
	f.snapshot.ObservedAt, f.snapshot.FreshUntil = clock, clock.Add(5*time.Second)
	f.snapshot.BindingResourceVersion = "new-complete-list"
	f.snapshot.Bindings[0].Resource.ResourceVersion = "new-object-version"
	f.snapshot.Bindings[0].Resource.Generation++
	f.snapshot.Bindings[0].Resource.SpecDigest[0]++
	f.snapshot.Bindings[0].Subjects[0].ID = "team-after-gap"
	f.trust.ObservedAt, f.trust.FreshUntil = clock, clock.Add(5*time.Second)
	r.Now = func() time.Time { clock = clock.Add(time.Microsecond); return clock }
	store.refreshErr = nil
	f.finished = make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan PermissionEpochResult, 1)
	go func() { done <- r.RunEpoch(ctx) }()
	select {
	case <-f.finished: // New watch starts only after the new initial acceptance.
	case result := <-done:
		t.Fatal("successor ended before fresh acceptance", result)
	case <-ctx.Done():
		t.Fatal("successor did not rebuild within test bound")
	}
	cancel()
	second := <-done
	if !errors.Is(second.Err, context.Canceled) || second.Suspended || len(store.begun) != 2 || len(f.accepted) != 2 || store.begun[0].Epoch == store.begun[1].Epoch || store.snapshots <= beforeSnapshots || f.trustCalls < beforeTrust+2 {
		t.Fatal("successor reused old guard/LIST/epoch or ignored parent cancellation", second)
	}
	old, fresh := f.accepted[0], f.accepted[1]
	if !fresh.ObservedAt.After(old.ObservedAt) || fresh.Epoch == old.Epoch || fresh.Bases[0].Continuous || fresh.Bases[0].Subjects[0].ID != "team-after-gap" || fresh.FreshUntil.After(f.snapshot.FreshUntil) || fresh.FreshUntil.After(f.trust.FreshUntil) {
		t.Fatal("new epoch renewed stale input or reconstructed pre-gap audience")
	}
}
