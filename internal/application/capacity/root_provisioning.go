package capacity

import (
	"context"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

type CapacityRootStore interface {
	ReadCapacityRoot(context.Context, RootBackingObservation) (*RootConfiguration, error)
	ReserveCapacityRoot(context.Context, RootBackingObservation) (RootConfiguration, error)
	RenewCapacityRoot(context.Context, RootBackingObservation, RootConfiguration) (RootConfiguration, error)
	PublishCapacityRoot(context.Context, RootBackingObservation, RootConfiguration) (RootConfiguration, error)
}
type CapacityRootCapture interface {
	BackCapacityRoot(context.Context, RootBackingObservation, RootConfiguration) (RootConfiguration, error)
}

// RootBackingCoordinator uses the same two purpose credentials as workload
// enrollment. A phase failure returns its retained receipt and never retries
// or guesses a missing result. A later current observation starts with exact
// SQL lookup; it may finish compatible transactional configuration only.
type RootBackingCoordinator struct {
	Store   CapacityRootStore
	Capture CapacityRootCapture
	Now     func() time.Time
}

func (c *RootBackingCoordinator) Reconcile(ctx context.Context, o RootBackingObservation) (RootConfiguration, error) {
	var zero RootConfiguration
	if c == nil || c.Store == nil || c.Capture == nil || c.Now == nil || ctx == nil || ctx.Err() != nil || !o.Valid(c.Now()) {
		return zero, cfg.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, o.FreshUntil)
	defer end()
	current := func() bool { return live.Err() == nil && o.Valid(c.Now()) }
	v, e := c.Store.ReadCapacityRoot(live, o)
	if e != nil || !current() {
		return zero, cfg.ErrUnavailable
	}
	if v == nil {
		x, err := c.Store.ReserveCapacityRoot(live, o)
		if err != nil || !current() {
			return zero, cfg.ErrUnavailable
		}
		// A concurrent first transaction may already have committed. Reserve
		// returns that exact original receipt, never a Fresh effect permit.
		v = &x
	}
	planned, plannedOK := o.ConfigurationUntil()
	if !plannedOK || v.PlannedUntil.Sub(v.RevisionObservedAt) != planned.Sub(o.ObservedAt) {
		return zero, cfg.ErrUnavailable
	}
	if !v.Valid() || v.RootID != o.RootID || v.PlanDigest != o.PlanDigest || v.ReconciledAt != nil {
		return zero, cfg.ErrUnavailable
	}
	// A new protected observation may reconcile an expired/near-expiry SQL
	// configuration. This is a distinct configuration grant, not a retry of an
	// expired permit. A lost result stops here; next invocation reads first.
	if !c.Now().Add(10 * time.Second).Before(v.PlannedUntil) {
		next, err := c.Store.RenewCapacityRoot(live, o, *v)
		if err != nil || !current() {
			return *v, cfg.ErrUnavailable
		}
		if !v.CompatibleRenewal(next, o) {
			return *v, cfg.ErrUnavailable
		}
		v = &next
	}
	if v.ReadyAt != nil {
		return *v, nil
	}
	if !c.Now().Before(v.PlannedUntil) {
		return *v, ErrEnrollmentPending
	}
	if v.CaptureBackedAt == nil {
		next, err := c.Capture.BackCapacityRoot(live, o, *v)
		if err != nil || !current() {
			return *v, cfg.ErrUnavailable
		}
		if !v.CompatibleContinuation(next) || next.CaptureBackedAt == nil || next.ReadyAt != nil {
			return *v, cfg.ErrUnavailable
		}
		v = &next
	}
	next, err := c.Store.PublishCapacityRoot(live, o, *v)
	if err != nil || !current() {
		return *v, cfg.ErrUnavailable
	}
	if !v.CompatibleContinuation(next) || !next.AdmissionReady(c.Now()) {
		return *v, cfg.ErrUnavailable
	}
	return next, nil
}
