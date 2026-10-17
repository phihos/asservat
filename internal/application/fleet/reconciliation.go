package fleet

import (
	"context"
	"sync/atomic"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// ConfigurationReconciler runs independent serial observation loops. A leader
// lease schedules this work; only the observers and their SQL transactions can
// accept state. Neither loop has a recovery activation method.
type ConfigurationReconciler struct {
	Fleet   *TrustObserver
	Owner   *OwnerConfigurationObserver
	running atomic.Bool
}

func (s *ConfigurationReconciler) Run(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.Fleet == nil || s.Owner == nil || s.Fleet.Settings == nil || s.Fleet.Projection == nil || s.Fleet.Now == nil || s.Owner.Reader == nil || s.Owner.Ledger == nil || s.Owner.Audit == nil || s.Owner.Acknowledgements == nil || s.Owner.Now == nil || !s.running.CompareAndSwap(false, true) {
		return value.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{}, 2)
	loop := func(observe func(context.Context) error) {
		defer func() { done <- struct{}{} }()
		for root.Err() == nil {
			call, end := context.WithTimeout(root, 5*time.Second)
			_ = observe(call) // failure remains unavailable in the observer's SQL projection
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
	go loop(s.Owner.Observe)
	<-root.Done()
	// A cancelled call still owns its SQL/provider resources until the actual
	// observer returns. Process-level termination is separate from a successful
	// joined shutdown; a timer cannot turn unfinished work into completion.
	cancel()
	for i := 0; i < 2; i++ {
		<-done
	}
	return root.Err()
}
