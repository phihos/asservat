package bootstrap

import (
	"context"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/fleet"
)

type liveOwnerSlowRoute struct {
	base  fleetapp.OwnerRouteReader
	calls int
}

func (r *liveOwnerSlowRoute) CurrentOwnerRoute(ctx context.Context, b fleet.OwnerBinding) (fleet.OwnerRoute, error) {
	r.calls++
	if r.calls > 1 {
		if e := liveOwnerProofWait(ctx); e != nil {
			return fleet.OwnerRoute{}, e
		}
	}
	return r.base.CurrentOwnerRoute(ctx, b)
}

type liveOwnerSlowProtection struct {
	base fleetapp.OwnerProtectionReader
}

func (p liveOwnerSlowProtection) ReadOwnerProtection(ctx context.Context, pool fleet.OwnerPool) (fleet.OwnerProtection, error) {
	if e := liveOwnerProofWait(ctx); e != nil {
		return fleet.OwnerProtection{}, e
	}
	return p.base.ReadOwnerProtection(ctx, pool)
}
func liveOwnerProofWait(ctx context.Context) error {
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
