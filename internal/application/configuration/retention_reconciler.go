package configuration

import (
	"context"
	"errors"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

type RetentionProtectionReader interface {
	RetentionProtection(context.Context) (privacy.SourceProtection, error)
}

// RetentionReconciler journals every guarded source transition. Audit/catch-up
// workers are independent. This role cannot promote a source to Ready.
type RetentionReconciler struct {
	RootID     string
	Source     privacy.PolicySourceRef
	Reader     RetentionListReader
	Watcher    RetentionWatcher
	Protection RetentionProtectionReader
	Review     RetentionBootstrapReviewReader
	Store      RetentionCheckpointStore
	Now        func() time.Time
	NewID      func() string
}
type retentionRun struct {
	r                   RetentionReconciler
	fence               RetentionFence
	journal             *RetentionJournal
	pendingObservations []RetentionObservation
	lastObservation     time.Time
}

func (r RetentionReconciler) valid() bool {
	return authorization.UUID(r.RootID) && ValidRetentionSource(r.Source) && r.Reader != nil && r.Watcher != nil && r.Protection != nil && r.Store != nil && r.Now != nil && r.NewID != nil
}
func (s *retentionRun) protection(ctx context.Context) (privacy.SourceProtection, error) {
	p, err := s.r.Protection.RetentionProtection(ctx)
	if err != nil {
		return privacy.SourceProtection{}, err
	}
	if p.SourceClusterID != s.r.Source.ClusterID || p.ControlNamespaceUID != s.r.Source.ControlNamespaceUID || p.Digest != s.r.Source.ProtectionDigest || !identity.Fresh(p.ObservedAt, p.FreshUntil, s.r.Now(), 5*time.Second) {
		return privacy.SourceProtection{}, value.ErrChanged
	}
	return p, nil
}
func (s *retentionRun) persist(ctx context.Context, event *PolicyEvent, review *value.RetentionBootstrapReview, until time.Time) error {
	if !s.r.Now().Before(until) {
		return value.ErrUnavailable
	}
	list, err := s.journal.HistoricalCheckpoint()
	if err != nil {
		return err
	}
	f := s.fence
	f.LeaseUntil = identity.Earlier(f.LeaseUntil, until)
	t := RetentionTransition{ID: s.r.NewID(), Fence: f, List: list, Event: event, Review: review}
	accepted, err := s.r.Store.AcceptRetention(ctx, t)
	if err != nil {
		return err
	}
	if !accepted.Record.Valid() || accepted.Record.RootID != s.r.RootID || accepted.Record.ID != t.ID || accepted.Record.Epoch != f.Epoch || accepted.Record.Sequence != f.Sequence+1 || accepted.Record.CheckpointDigest != RetentionTransitionDigest(t) || RetentionTransitionDigest(accepted.Transition) != RetentionTransitionDigest(t) {
		return value.ErrChanged
	}
	if err = s.journal.Accepted(list); err != nil {
		return err
	}
	s.fence.Sequence = accepted.Record.Sequence
	return nil
}
func (s *retentionRun) start(ctx context.Context) error {
	first, err := s.protection(ctx)
	if err != nil {
		return err
	}
	start, err := s.r.Store.BeginRetention(ctx, s.r.RootID, s.r.Source, s.r.NewID())
	if err != nil {
		return err
	}
	s.fence = start.Fence
	if !s.fence.Valid() || s.fence.RootID != s.r.RootID || s.fence.Source != s.r.Source || !s.r.Now().Before(s.fence.LeaseUntil) {
		return value.ErrChanged
	}
	if c := start.Checkpoint; c != nil {
		if !c.Record.Valid() || c.Record.RootID != s.r.RootID || c.Record.Sequence != s.fence.Sequence || c.Transition.Fence.Source != s.r.Source || RetentionTransitionDigest(c.Transition) != c.Record.CheckpointDigest {
			return value.ErrChanged
		}
		// Never relist to initialize a resumed epoch: the next watch begins at
		// the durable cursor, even when its original observation has expired.
		s.journal, err = ResumeRetentionJournal(c.Transition.List)
		if err != nil {
			return err
		}
		if !identity.Text(start.ResumeCursor, 128) || start.ResumeCursor == "0" {
			return value.ErrChanged
		}
		if err = s.journal.Apply(PolicyEvent{Type: "BOOKMARK", ResourceVersion: start.ResumeCursor}); err != nil {
			return err
		}
		_, err = s.protection(ctx)
		return err
	}
	if s.fence.Sequence != 0 {
		return value.ErrChanged
	}
	list, err := s.r.Reader.RetentionPolicyList(ctx)
	if err != nil {
		return err
	}
	if list.Snapshot.SourceClusterID != s.r.Source.ClusterID || list.Snapshot.ControlNamespaceUID != s.r.Source.ControlNamespaceUID || list.Snapshot.Hub != s.r.Source.Hub {
		return value.ErrChanged
	}
	var review *value.RetentionBootstrapReview
	if len(list.Snapshot.Policies) > 0 {
		if s.r.Review == nil {
			return value.ErrDenied
		}
		r, err := s.r.Review.InitialRetentionReview(ctx)
		if err != nil {
			return err
		}
		review = &r
	}
	last, err := s.protection(ctx)
	if err != nil {
		return err
	}
	until := identity.Earlier(first.FreshUntil, last.FreshUntil)
	if !s.r.Now().Before(until) {
		return value.ErrUnavailable
	}
	list.Snapshot.FreshUntil = identity.Earlier(list.Snapshot.FreshUntil, until)
	if review != nil {
		list.Snapshot.FreshUntil = identity.Earlier(list.Snapshot.FreshUntil, review.FreshUntil)
	}
	if err = CheckInitialRetention(list.Snapshot, s.r.Source.ProtectionDigest, review, s.r.Now()); err != nil {
		return err
	}
	s.journal, err = NewRetentionJournal(list, s.r.Now())
	if err != nil {
		return err
	}
	return s.persist(ctx, nil, review, until)
}
func (s *retentionRun) maintain(ctx context.Context) error {
	if !s.lastObservation.IsZero() && s.r.Now().Before(s.lastObservation) {
		return value.ErrUnavailable
	}
	first, err := s.protection(ctx)
	if err != nil {
		return err
	}
	if s.fence.LeaseUntil.Sub(s.r.Now()) < 10*time.Second {
		f, err := s.r.Store.RenewRetention(ctx, s.fence)
		if err != nil {
			return err
		}
		if !f.Valid() || f.RootID != s.fence.RootID || f.Epoch != s.fence.Epoch || f.Source != s.fence.Source || f.Sequence != s.fence.Sequence || !s.r.Now().Before(f.LeaseUntil) || f.LeaseUntil.Sub(s.r.Now()) > 30*time.Second {
			return value.ErrChanged
		}
		s.fence = f
	}
	if s.lastObservation.IsZero() || !s.r.Now().Before(s.lastObservation.Add(time.Second)) {
		s.lastObservation = s.r.Now()
		list, err := s.r.Reader.RetentionPolicyList(ctx)
		if err != nil {
			return err
		}
		last, err := s.protection(ctx)
		if err != nil {
			return err
		}
		proof := first
		proof.FreshUntil = identity.Earlier(first.FreshUntil, last.FreshUntil)
		if !identity.Fresh(proof.ObservedAt, proof.FreshUntil, s.r.Now(), 5*time.Second) {
			return value.ErrUnavailable
		}
		// At most one original observation per second, each valid for at most
		// five seconds. Keep a bounded window so a bookmark can confirm the
		// freshest covered LIST instead of an almost-expired first waiter.
		if len(s.pendingObservations) == 5 {
			s.discardObservations(1)
		}
		s.pendingObservations = append(s.pendingObservations, RetentionObservation{List: list, Protection: proof})
	}
	return s.observe(ctx)
}
func (s *retentionRun) observe(ctx context.Context) error {
	for i := len(s.pendingObservations) - 1; i >= 0; i-- {
		o := s.pendingObservations[i]
		o.Fence = s.fence
		if !s.r.Now().Before(o.List.Snapshot.FreshUntil) || !s.r.Now().Before(o.Protection.FreshUntil) {
			s.discardObservations(i + 1)
			return nil
		}
		err := s.r.Store.ObserveRetention(ctx, o)
		if errors.Is(err, value.ErrRetentionHistoryBehind) {
			continue
		}
		if err == nil || errors.Is(err, value.ErrRetentionObservationObsolete) {
			s.discardObservations(i + 1)
			return nil
		}
		return err
	}
	return nil
}
func (s *retentionRun) discardObservations(n int) {
	clear(s.pendingObservations[:n])
	s.pendingObservations = s.pendingObservations[n:]
}

func (s *retentionRun) observationDelay() time.Duration {
	remaining := s.lastObservation.Add(time.Second).Sub(s.r.Now())
	if remaining < 0 {
		return 0
	}
	// A rollback must reach maintain's rejection promptly, not postpone it.
	if remaining > time.Second {
		return time.Second
	}
	return remaining
}
func (r RetentionReconciler) Run(ctx context.Context) (result error) {
	defer func() {
		if ctx.Err() != nil {
			result = ctx.Err()
		}
	}()
	if !r.valid() {
		return value.ErrInvalid
	}
	s := &retentionRun{r: r}
	defer func() {
		if s.fence.Epoch != "" {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = r.Store.SuspendRetention(cleanup, s.fence)
		}
	}()
	if err := s.start(ctx); err != nil {
		return err
	}
	for {
		if err := s.maintain(ctx); err != nil {
			return err
		}
		watch, err := r.Watcher.WatchRetentionPolicies(ctx, s.journal.Cursor())
		if err != nil {
			return err
		}
		err = s.consume(ctx, watch)
		if !errors.Is(err, io.EOF) {
			return err
		}
	}
}
func (s *retentionRun) consume(ctx context.Context, watch RetentionWatch) error {
	child, cancel := context.WithCancel(ctx)
	// Anchor renewal to the last actual observation. A fixed ticker whose
	// phase precedes lastObservation can repeatedly skip otherwise healthy
	// cycles when a guard/API call's duration changes by a few milliseconds.
	timer := time.NewTimer(s.observationDelay())
	defer timer.Stop()
	type item struct {
		event PolicyEvent
		err   error
	}
	queue := make(chan item, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			e, err := watch.Next(child)
			select {
			case queue <- item{e, err}:
			case <-child.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() { cancel(); watch.Close(); <-done }()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if err := s.maintain(ctx); err != nil {
				return err
			}
			timer.Reset(s.observationDelay())
		case got := <-queue:
			if got.err != nil {
				return got.err
			}
			proof, err := s.protection(ctx)
			if err != nil {
				return err
			}
			if err = s.journal.Apply(got.event); err != nil {
				return err
			}
			if got.event.Type == "BOOKMARK" {
				f := s.fence
				f.LeaseUntil = identity.Earlier(f.LeaseUntil, proof.FreshUntil)
				if err = s.r.Store.AdvanceRetentionCursor(ctx, f, got.event.ResourceVersion); err != nil {
					return err
				}
				if err = s.observe(ctx); err != nil {
					return err
				}
				continue
			}
			if err = s.persist(ctx, &got.event, nil, proof.FreshUntil); err != nil {
				return err
			}
			if err = s.observe(ctx); err != nil {
				return err
			}
		}
	}
}
