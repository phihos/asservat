package fleet

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
)

// A purpose-fixed provider consumes only an independently spent and audited
// permit. It cannot admit a process, choose another purpose or activate a leaf.
type ConnectorCredentialIssuer interface {
	SignConnectorCredential(context.Context, value.ConnectorCredentialPermit, []byte) (value.IssuedConnectorCredential, error)
}

// Current profile reads cannot create or reactivate accepted issuer authority.
type ConnectorCredentialProfiles interface {
	ReadConnectorCredentialProfile(context.Context, value.PeerBinding) (value.ConnectorCredentialObservation, error)
}

// The source producer returns protected configuration, including suspension.
// Its observation can stage/fence candidate facts; it cannot activate a peer.
type ConnectorIdentitySourceReader interface {
	ReadConnectorIdentitySource(context.Context) (value.ConnectorIdentitySource, error)
}

// The private ingress supplies an owned buffer for this request; the concrete
// attester clears it. No bootstrap secret or human credential is involved.
type ConnectorPodToken interface {
	ReadConnectorPodToken(context.Context) ([]byte, error)
}
type ConnectorProcessProofReader interface {
	ReadConnectorProcessProof(context.Context, value.ConnectorProcessRequest) (value.ConnectorProcessProof, error)
}
