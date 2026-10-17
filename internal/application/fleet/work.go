package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

type WorkTrustReader interface {
	WorkTrust(context.Context, value.Receiver) (value.WorkTrust, error)
}

// RunActionVerifier authenticates one purpose. Its output still needs current
// authorization, immutable scope/reference resolution and a durable start journal.
type RunActionVerifier interface {
	VerifyRunAction(context.Context, []byte, value.Receiver) (value.AuthenticatedAction, error)
}
