package kubernetes

import (
	"context"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

var _ app.ConnectorObservationProofReader = (*ConnectorProcessAttester)(nil)

// ReadConnectorObservationProof retains both full source reads, online token
// reviews and native workload/guard checks of ordinary process attestation.
// The returned source is one of those actual reads, not reconstructed from an
// installed pin. Neither this proof nor its source grants SQL activation.
func (s *ConnectorProcessAttester) ReadConnectorObservationProof(ctx context.Context, r value.ConnectorProcessRequest) (value.ConnectorObservationAttestation, error) {
	proof, source, err := s.readConnectorProcessSourceAttestation(ctx, r, false)
	if err != nil {
		return value.ConnectorObservationAttestation{}, err
	}
	return value.ConnectorObservationAttestation{Proof: proof, Source: source}, nil
}
