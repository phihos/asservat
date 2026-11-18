package fleet

import (
	"context"
	"sync/atomic"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// ConfigurationReconciler runs the serial owner configuration observation
// loop. A leader lease schedules this work; only the observer and its SQL
// transactions can accept state.
type ConfigurationReconciler struct {
	Owner   *OwnerConfigurationObserver
	running atomic.Bool
}

// Run maintains the owner's original source interval until leadership ends.
func (s *ConfigurationReconciler) Run(ctx context.Context) error {
	if s == nil || ctx == nil || s.Owner == nil || !s.running.CompareAndSwap(false, true) {
		return value.ErrInvalid
	}
	for ctx.Err() == nil {
		call, end := context.WithTimeout(ctx, 5*time.Second)
		_ = s.Owner.Observe(call)
		end()
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return ctx.Err()
}
