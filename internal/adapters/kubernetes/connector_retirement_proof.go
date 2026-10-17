package kubernetes

import (
	"context"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

var _ app.ConnectorRetirementProofReader = (*ConnectorProcessAttester)(nil)

// ReadConnectorRetirementProof retains the concrete token, account, controller,
// key and native guard checks, including both original source observations. It
// accepts only a protected suspended+retiring source. There is no lookup fallback
// after Pod deletion or authority to issue a replacement process or certificate.
func (s *ConnectorProcessAttester) ReadConnectorRetirementProof(ctx context.Context, r value.ConnectorProcessRequest) (value.ConnectorRetirementProof, error) {
	p, err := s.readConnectorProcessAttestation(ctx, r, true)
	if err != nil {
		return value.ConnectorRetirementProof{}, err
	}
	return value.ConnectorRetirementProof(p), nil
}
