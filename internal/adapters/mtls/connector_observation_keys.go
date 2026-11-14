package mtls

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// connectorObservationKeys is a private process-owned snapshot, never a source
// observation, independent SQL activation or authority for metadata. It carries
// no private key or signer; the process pointer is only a replacement veto.
type connectorObservationKeys struct {
	process              *connectorOwnedProcess
	request              value.ConnectorProcessRequest
	leaf                 value.ConnectorCredentialCertificate
	chain                [][]byte
	keys                 [2]artifact.Digest
	observedAt, runUntil time.Time
}
