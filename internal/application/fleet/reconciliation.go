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
	// WaitOwnerChange returns a confirmed deletion cursor, or an empty cursor for a relist.
	WaitOwnerChange(context.Context, string) (string, error)
}

type OwnerConfigurationLedger interface {
	ApplyOwnerConfiguration(context.Context, string, value.OwnerConfigurationObservation) error
}

type ConfigurationReconciler struct {
	Source OwnerConfigurationSource
	Ledger OwnerConfigurationLedger
}

// The worker lease selects one reconciler. Read at startup, on a source change,
// and after a watch interruption. A transient failure preserves accepted state.
func (r *ConfigurationReconciler) Run(ctx context.Context) error {
	if r == nil || r.Source == nil || r.Ledger == nil || ctx == nil {
		return value.ErrInvalid
	}
	var deletion string
	for ctx.Err() == nil {
		call, end := context.WithTimeout(ctx, 5*time.Second)
		var observed value.OwnerConfigurationObservation
		rv := deletion
		var err error
		if rv == "" {
			observed, rv, err = r.Source.OwnerSourceSnapshot(call)
		}
		if err == nil {
			if observed.ObservedAt.IsZero() {
				deletion = rv
			}
			err = r.Ledger.ApplyOwnerConfiguration(call, rv, observed)
			// A conflicting Helm generation was durably fenced at this cursor.
			if errors.Is(err, value.ErrConflict) {
				err = nil
			}
		}
		end()
		if err == nil {
			// An applied deletion stands even if the watch or the next LIST fails.
			deletion, err = r.Source.WaitOwnerChange(ctx, rv)
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
