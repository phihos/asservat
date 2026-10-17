package fleet

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
)

// Only the local observation conversation consumes this additional full source
// result. Ordinary process proof and retirement proof contracts stay unchanged.
type ConnectorObservationProofReader interface {
	ReadConnectorObservationProof(context.Context, value.ConnectorProcessRequest) (value.ConnectorObservationAttestation, error)
}

// The concrete local native reader proves this exact installed connector
// template and current Pod/controller/guard. It is never a remote API proxy.
type ConnectorObservationWorkloadReader interface {
	ObserveConnectorWorkload(context.Context, value.ConnectorProcessIdentity, string) (value.ConnectorObservationWorkload, error)
}
