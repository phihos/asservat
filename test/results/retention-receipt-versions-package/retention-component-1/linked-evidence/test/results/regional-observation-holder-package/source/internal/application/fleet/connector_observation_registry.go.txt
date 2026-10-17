package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// ConnectorObservationRegistry binds one conversation's genuinely fresh source
// replies to the original installed registry profile. The concrete adapter
// retains its original scoped ledger; it cannot select credentials from a peer.
// The source is not activation authority and the exact current SQL leaf read
// still brackets its I/O with two independent source observations.
type ConnectorObservationRegistry interface {
	ReadConnectorObservationRegistration(context.Context, value.ConnectorCredentialProfile, ConnectorIdentitySourceReader, value.ConnectorCredentialCertificate) (ConnectorLeafRegistration, error)
}
