package fleet

import (
	"context"
	"sync"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// This mailbox is specific to the fresh configuration worker. One immutable
// active audit and one unselected notification are the entire local inventory.
// SQL owns uncertainty/history; dropping a hint never erases persisted spend.
type workerOwnerAudit struct {
	mu        sync.Mutex
	owner     *OwnerConfigurationObserver
	admission *WorkerRuntimeAdmission
	known     *value.OwnerConfiguration
	pending   *ownerConfigurationAuditCandidate
	active    *ownerConfigurationAuditCandidate
	cancel    context.CancelFunc
	wake      chan struct{}
}

func (s *workerOwnerAudit) invalidate() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.pending = nil
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
}

func (s *workerOwnerAudit) noteSource(configuration value.OwnerConfiguration) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.known != nil && !s.known.Equal(configuration)
	copy := configuration.Clone()
	s.known = &copy
	if changed {
		s.pending = nil
		if s.cancel != nil {
			s.cancel()
		}
	}
	return changed
}

func (s *workerOwnerAudit) notify(c ownerConfigurationAuditCandidate, acknowledged bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || !c.observation.Valid(s.owner.Now()) || !s.owner.Now().Before(c.until) {
		s.pending = nil
		if s.cancel != nil {
			s.cancel()
		}
		return
	}
	configuration := c.observation.Configuration
	changed := s.known != nil && !s.known.Equal(configuration)
	copy := configuration.Clone()
	s.known = &copy
	if changed || c.superseded {
		// Known supersession permanently closes the old selected audit. Do not
		// turn its pending slot into a new revision's attempt in this pass. The
		// next independent ordinary observation may offer that new revision.
		s.pending = nil
		if s.cancel != nil {
			s.cancel()
		}
		return
	}
	if acknowledged {
		s.pending = nil
		if s.cancel != nil {
			s.cancel()
		}
		return
	}
	if s.pending != nil {
		if !s.pending.observation.Configuration.Equal(configuration) ||
			!c.observation.ObservedAt.After(s.pending.observation.ObservedAt) {
			return
		}
	}
	// Only this not-yet-selected same-revision notification may receive a
	// newer independently observed interval. The active pointer never changes.
	c.observation.Configuration = configuration.Clone()
	s.pending = &c
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *workerOwnerAudit) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		}
		// The mailbox candidate is deliberately still unselected during both
		// FIFO and source-notice waits. Independent observations may replace
		// only that pending candidate, never a later active one.
		lease, err := s.admission.WaitOwnerAudit(ctx)
		if err != nil {
			continue
		}
		if lease.AwaitFleetObservation() != nil {
			lease.Release()
			continue
		}
		s.mu.Lock()
		if ctx.Err() != nil || lease.Context().Err() != nil {
			s.mu.Unlock()
			lease.Release()
			if ctx.Err() != nil {
				return
			}
			continue
		}
		c := s.pending
		s.pending = nil
		if c == nil || s.known == nil || !s.known.Equal(c.observation.Configuration) || !c.observation.Valid(s.owner.Now()) || !s.owner.Now().Before(c.until) {
			s.mu.Unlock()
			lease.Release()
			continue
		}
		call, cancel := context.WithDeadline(lease.Context(), c.until)
		s.active, s.cancel = c, cancel
		s.mu.Unlock()
		err = s.owner.auditObserved(call, *c)
		cancel()
		s.mu.Lock()
		s.active, s.cancel = nil, nil
		if err == nil && s.pending != nil && s.pending.observation.Configuration.Equal(c.observation.Configuration) {
			// Positive acknowledgement makes another queued same-record attempt
			// unnecessary. The next SQL observer also reads it passively.
			s.pending = nil
		}
		// Failed/unknown work is not retried here. A remaining notification came
		// from a separate actual source+SQL observation and owns its own end.
		s.mu.Unlock()
		lease.Release()
	}
}

// RunWithIndependentOwnerAudit is selected only by the fresh worker2 loader.
// Both source loops retain their one-second-after-completion cadence, while
// the fixed audit actor may wait for the shared expensive-operation admission.
// It neither accepts recovery nor implements a generic background task queue.
func (s *ConfigurationReconciler) RunWithIndependentOwnerAudit(ctx context.Context, admission *WorkerRuntimeAdmission) error {
	if s == nil || admission == nil || admission.self != admission || ctx == nil || ctx.Err() != nil || s.Fleet == nil || s.Owner == nil || s.Fleet.Settings == nil || s.Fleet.Projection == nil || s.Fleet.Now == nil || s.Owner.Reader == nil || s.Owner.Ledger == nil || s.Owner.Audit == nil || s.Owner.Acknowledgements == nil || s.Owner.Now == nil || !s.running.CompareAndSwap(false, true) {
		return value.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	defer cancel()
	audit := &workerOwnerAudit{owner: s.Owner, admission: admission, wake: make(chan struct{}, 1)}
	done := make(chan struct{}, 3)
	loop := func(observe func(context.Context) error) {
		defer func() { done <- struct{}{} }()
		for root.Err() == nil {
			call, end := context.WithTimeout(root, 5*time.Second)
			_ = observe(call)
			end()
			timer := time.NewTimer(time.Second)
			select {
			case <-root.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
	go loop(s.Fleet.Reconcile)
	go loop(func(ctx context.Context) error {
		c, ack, err := s.Owner.observeForAuditNotifying(ctx, audit)
		audit.notify(c, ack, err)
		return err
	})
	go func() { defer func() { done <- struct{}{} }(); audit.run(root) }()
	<-root.Done()
	cancel()
	for i := 0; i < 3; i++ {
		<-done
	}
	return root.Err()
}
