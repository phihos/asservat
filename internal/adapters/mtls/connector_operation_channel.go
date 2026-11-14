package mtls

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ConnectorObservationOperationChannel belongs to one actual regional TLS stream. Its
// methods implement four real source-value replies within two native brackets,
// one bounded local metadata
// read and the exact final receipt. The transport still owns framing/socket
// cancellation and must join both this channel and the actual stream at Close.
// A standby candidate authenticates only the handshake, not later metadata.
type ConnectorObservationOperationChannel struct {
	ctx                                  context.Context
	cancel                               context.CancelFunc
	exchangeID                           string
	pin                                  value.OwnerObservationPin
	state                                tls.ConnectionState
	owner                                value.OwnerCertificate
	leaf                                 value.ConnectorCredentialCertificate
	keys                                 connectorObservationKeys
	verifier                             *OwnerPeerVerifier
	candidates                           *app.OwnerObservationCandidateSelection
	registry                             app.OwnerCertificateRegistry
	producer                             *ConnectorObservationOperationProducer
	metadata                             app.ClusterObservationExchange
	now                                  func() time.Time
	mu                                   sync.Mutex
	busy, failed, closed, read, received bool
	ordinal                              int
	request                              value.OwnerObservationRequest
	origin                               *ownerOperationObservation
	operation                            *connectorProducedOperation
	lastOwner                            *ownerOperationObservation
	digest                               artifact.Digest
	until                                time.Time
	untilBy                              string
	joined                               sync.WaitGroup
}
