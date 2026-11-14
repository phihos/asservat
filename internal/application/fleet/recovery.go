package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// Read-only current recovery state; no method here can activate an installation.
type RecoveryReader interface {
	RecoveryState(context.Context) (value.RecoveryState, error)
}
