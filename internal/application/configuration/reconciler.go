package configuration

import (
	"context"
	"errors"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// BindingReconciler accepts explicit AccessBindings from a qualified Kubernetes
// installation. Inheritance requires its own protected source reconciler and is
// not inferred from a configured PermissionSource. A single Run owns one epoch;
// failure/cancellation suspends it. A supervisor may restart with a new epoch.
// Dependencies are ports; production composition must supply qualified readers.
type BindingReconciler struct {
	RootID  string
	Reader  PermissionReader
	Watcher BindingWatcher
	Trust   PermissionTrustReader
	Review  BootstrapReviewReader
	Store   PermissionStore
	Now     func() time.Time
	NewID   func() string
}

type bindingRun struct {
	r          BindingReconciler
	fence      value.PermissionFence
	journal    *BindingJournal
	trustUntil time.Time
}

func (r BindingReconciler) valid() bool {
	return authorization.UUID(r.RootID) && r.Reader != nil && r.Watcher != nil && r.Trust != nil && r.Store != nil && r.Now != nil && r.NewID != nil
}
func (r BindingReconciler) trust(ctx context.Context) (PermissionTrust, error) {
	t, err := r.Trust.PermissionTrust(ctx)
	if err != nil {
		return PermissionTrust{}, err
	}
	if t.Digest == ([32]byte{}) || !identity.Fresh(t.ObservedAt, t.FreshUntil, r.Now(), 5*time.Second) {
		return PermissionTrust{}, value.ErrUnavailable
	}
	return t, nil
}
func (s *bindingRun) guardedSnapshot(ctx context.Context, first PermissionTrust) (value.Snapshot, error) {
	snapshot, err := s.r.Reader.PermissionSnapshot(ctx)
	if err != nil {
		return value.Snapshot{}, err
	}
	last, err := s.r.trust(ctx)
	if err != nil {
		return value.Snapshot{}, err
	}
	if first.Digest != s.fence.TrustDigest || last.Digest != first.Digest || !identity.Fresh(first.ObservedAt, first.FreshUntil, s.r.Now(), 5*time.Second) {
		return value.Snapshot{}, value.ErrChanged
	}
	s.trustUntil = identity.Earlier(first.FreshUntil, last.FreshUntil)
	snapshot.FreshUntil = identity.Earlier(snapshot.FreshUntil, s.trustUntil)
	return snapshot, nil
}
func (s *bindingRun) accept(ctx context.Context, refresh bool) error {
	if !s.r.Now().Before(s.trustUntil) {
		return value.ErrUnavailable
	}
	if err := s.journal.Constrain(s.trustUntil); err != nil {
		return err
	}
	b, err := s.journal.Prepare(s.fence, s.r.NewID(), s.r.Now())
	if err != nil {
		return err
	}
	if refresh {
		err = s.r.Store.RefreshPermissions(ctx, b)
		if err == nil {
			return s.journal.Refreshed(b.RequestID)
		}
		// Identical input may have an expired member. Accept that removal as a
		// new transition; an epoch/sequence conflict still fails in the store.
		if !errors.Is(err, value.ErrChanged) {
			return err
		}
	}
	accepted, err := s.r.Store.AcceptPermissions(ctx, b)
	if err != nil {
		return err
	}
	if err = s.journal.Accepted(accepted); err != nil {
		return err
	}
	s.fence = accepted.PermissionFence
	return nil
}
func (s *bindingRun) start(ctx context.Context) error {
	first, err := s.r.trust(ctx)
	if err != nil {
		return err
	}
	s.fence, err = s.r.Store.BeginPermissions(ctx, s.r.RootID, s.r.NewID(), first.Digest)
	if err != nil {
		return err
	}
	snapshot, err := s.guardedSnapshot(ctx, first)
	if err != nil {
		return err
	}
	s.journal, err = NewBindingJournal(snapshot, s.r.Now())
	if err != nil {
		return err
	}
	if !s.fence.Initialized && len(snapshot.Bindings) > 0 {
		if s.r.Review == nil {
			return value.ErrDenied
		}
		review, e := s.r.Review.InitialPermissionReview(ctx)
		if e != nil {
			return e
		}
		if err = s.journal.SetInitialReview(review, s.r.Now()); err != nil {
			return err
		}
	}
	return s.accept(ctx, false)
}

var errWatchBehind = errors.New("permission watch has not reached current complete list")

func (s *bindingRun) refresh(ctx context.Context) error {
	first, err := s.r.trust(ctx)
	if err != nil {
		return reconcileStep("trust", err)
	}
	snapshot, err := s.guardedSnapshot(ctx, first)
	if err != nil {
		return reconcileStep("snapshot", err)
	}
	if err = s.journal.Confirm(snapshot, s.r.Now()); err != nil {
		// Do not replace a journal with a newer LIST and thereby skip an
		// intermediate owner. Process queued events, then retry the full LIST.
		if !s.r.Now().Before(s.journal.until) {
			return reconcileStep("confirm-expired", value.ErrUnavailable)
		}
		return errWatchBehind
	}
	if s.fence.LeaseUntil.Sub(s.r.Now()) < 10*time.Second {
		s.fence, err = s.r.Store.RenewPermissions(ctx, s.fence)
		if err != nil {
			return reconcileStep("renew", err)
		}
	}
	if err = s.accept(ctx, true); err != nil {
		return reconcileStep("accept", err)
	}
	return nil
}

// Run keeps event delivery bounded to one queued transition and processes each
// through SQL before reading the next. Full LISTs renew deny completeness;
// bookmarks and watch traffic do not. Audit publication is an independent role:
// the store keeps new allows unavailable until its exact record is acknowledged.
func (r BindingReconciler) Run(ctx context.Context) error {
	if !r.valid() {
		return value.ErrInvalid
	}
	s := &bindingRun{r: r}
	defer func() {
		if s.fence.Epoch != "" {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			// Failure here leaves the original <=5s permission deadline and the
			// bounded leader lease; no goroutine keeps renewing either of them.
			_ = r.Store.SuspendPermissions(cleanup, s.fence)
		}
	}()
	if err := s.start(ctx); err != nil {
		return reconcileStep("start", err)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		watch, err := r.Watcher.WatchBindings(ctx, s.journal.Cursor())
		if err != nil {
			return reconcileStep("watch", err)
		}
		err = s.consume(ctx, watch, ticker.C)
		if !errors.Is(err, io.EOF) {
			return err
		}
	}
}
func (s *bindingRun) consume(ctx context.Context, watch BindingWatch, ticks <-chan time.Time) error {
	child, cancel := context.WithCancel(ctx)
	type result struct {
		event value.BindingEvent
		err   error
	}
	queue := make(chan result, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			e, eerr := watch.Next(child)
			select {
			case queue <- result{e, eerr}:
			case <-child.Done():
				return
			}
			if eerr != nil {
				return
			}
		}
	}()
	defer func() { cancel(); watch.Close(); <-done }()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			if err := s.refresh(ctx); err != nil && !errors.Is(err, errWatchBehind) {
				return reconcileStep("refresh", err)
			}
		case item := <-queue:
			if item.err != nil {
				if errors.Is(item.err, io.EOF) {
					return item.err
				}
				return reconcileStep("watch-next", item.err)
			}
			if err := s.journal.Apply(item.event); err != nil {
				return reconcileStep("apply", err)
			}
			if item.event.Type != "BOOKMARK" {
				if err := s.accept(ctx, false); err != nil {
					return reconcileStep("accept", err)
				}
			}
		}
	}
}

// reconcileStepError names the phase that stopped a permission epoch; the
// hub-worker logs it (ADR-197 runs 23a/23b: repeated stops, no cause). Labels
// compose with nested fixed steps.
type reconcileStepError struct {
	step string
	err  error
}

func reconcileStep(step string, err error) error { return &reconcileStepError{step, err} }

func (e *reconcileStepError) Error() string { return e.step }
func (e *reconcileStepError) Unwrap() error { return e.err }
func (e *reconcileStepError) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}
