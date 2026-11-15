package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// APIContextReceiverCheck retains the exact actual peer and process selected by
// one connection. Fresh checks never restore a lost human request owner.
type APIContextReceiverCheck func(context.Context) (value.APIContextReceiver, error)

// Enumeration returns candidates only. Consumers must use exact current route,
// peer TLS and activated registry checks before every connection/attachment.
type APIContextOwnerCandidatesReader interface {
	ReadContextStartOwners(context.Context) (value.APIContextOwnerCandidates, error)
}
