package bootstrap

import (
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"context"
	"time"
)

// The active constructor invokes this only after selecting the original passive
// disposition. It is a finite read-only prerequisite, never authority retained
// for later effects; the activation SQL facet independently checks incarnation.
func initialPreparationSchemaPreflight(ctx context.Context, capability string, verify func(context.Context) (time.Time, error), now func() time.Time) error {
	if capability == "" {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || capability != contracts.InitialSchemaProtocol || verify == nil || now == nil {
		return mounts.ErrUnavailable
	}
	original := now().Add(5 * time.Second)
	bounded, stop := context.WithDeadline(ctx, original)
	defer stop()
	until, err := verify(bounded)
	if err != nil {
		return err
	}
	if bounded.Err() != nil || !now().Before(original) || !now().Before(until) {
		return mounts.ErrUnavailable
	}
	return nil
}
