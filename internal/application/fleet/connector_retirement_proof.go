package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// This separate port is for a protected suspended-and-retiring source's audit
// actor only. Its proof cannot be used for process or certificate admission.
type ConnectorRetirementProofReader interface {
	ReadConnectorRetirementProof(context.Context, value.ConnectorProcessRequest) (value.ConnectorRetirementProof, error)
}
