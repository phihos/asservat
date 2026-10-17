package fleet

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
)

// Read-only current recovery state; no method here can activate an installation.
type RecoveryReader interface {
	RecoveryState(context.Context) (value.RecoveryState, error)
}
