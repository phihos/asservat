package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// APIContextReceiverCheck retains the exact actual peer and process selected by
// one connection. Fresh checks never restore a lost human request owner.
type APIContextReceiverCheck func(context.Context) (value.APIContextReceiver, error)
