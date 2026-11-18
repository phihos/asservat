package fleet

import (
	"context"
	"errors"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// OwnerConfigurationSource returns a complete named LIST and its watch cursor.
// An empty observation at a known cursor represents an absent or invalid source.
type OwnerConfigurationSource interface {
	OwnerSourceSnapshot(context.Context) (value.OwnerConfigurationObservation, string, error)
	WaitOwnerChange(context.Context, string) error
}

type ConfigurationReconciler struct {
	Source OwnerConfigurationSource
	Ledger OwnerConfigurationLedger
	Now    func() time.Time
}

// The worker lease selects one reconciler. Read at startup, on a source change,
// and after a watch interruption. A transient failure preserves accepted state.
func (r *ConfigurationReconciler) Run(ctx context.Context) error {
	if r == nil || r.Source == nil || r.Ledger == nil || r.Now == nil || ctx == nil {
		return value.ErrInvalid
	}
	for ctx.Err() == nil {
		call, end := context.WithTimeout(ctx, 5*time.Second)
		start := r.Now()
		observed, rv, err := r.Source.OwnerSourceSnapshot(call)
		if err == nil {
			if observed.CurrentSource(r.Now()) {
				err = r.Ledger.ObserveOwnerConfiguration(call, observed)
				// The ledger already committed the negative fence for a conflicting generation.
				if errors.Is(err, value.ErrConflict) {
					err = nil
				}
			} else {
				err = r.Ledger.FenceOwnerConfiguration(call, start)
			}
		}
		end()
		if err == nil {
			err = r.Source.WaitOwnerChange(ctx, rv)
		}
		if err != nil && ctx.Err() == nil {
			// Back off only after failed I/O; a healthy idle watch needs no timer.
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}
	return ctx.Err()
}
