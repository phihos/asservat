package fleet

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

type OwnerConfigurationLedger interface {
	ObserveOwnerConfiguration(context.Context, value.OwnerConfigurationObservation) error
	FenceOwnerConfiguration(context.Context, time.Time) error
}

type OwnerConfigurationObserver struct {
	Reader OwnerConfigurationReader
	Ledger OwnerConfigurationLedger
	Now    func() time.Time
}

func (s *OwnerConfigurationObserver) Observe(ctx context.Context) error {
	if s == nil || ctx == nil || s.Reader == nil || s.Ledger == nil || s.Now == nil {
		return value.ErrInvalid
	}
	start := s.Now()
	fence := func(at time.Time) {
		cleanup, end := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer end()
		_ = s.Ledger.FenceOwnerConfiguration(cleanup, at)
	}
	o, err := s.Reader.ReadOwnerConfiguration(ctx)
	if err != nil || !o.Valid(s.Now()) || ctx.Err() != nil {
		fence(start)
		return value.ErrUnavailable
	}
	o.Configuration = o.Configuration.Clone()
	ctx, end := context.WithDeadline(ctx, o.FreshUntil)
	defer end()
	if err := s.Ledger.ObserveOwnerConfiguration(ctx, o); err != nil {
		fence(o.ObservedAt)
		return err
	}
	if ctx.Err() != nil || !o.Valid(s.Now()) {
		return value.ErrUnavailable
	}
	return nil
}
