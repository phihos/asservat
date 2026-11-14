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

// ConnectorObservationChannel belongs to one actual regional TLS stream. Its
// methods implement only four fresh proof replies, one bounded local metadata
// read and the exact final receipt. The transport still owns framing/socket
// cancellation and must join both this channel and the actual stream at Close.
// A standby candidate authenticates only the handshake, not later metadata.
type ConnectorObservationChannel struct {
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
	producer                             *ConnectorObservationProducer
	metadata                             app.ClusterObservationExchange
	now                                  func() time.Time
	mu                                   sync.Mutex
	busy, failed, closed, read, received bool
	ordinal                              int
	request                              value.OwnerObservationRequest
	origin                               *value.OwnerObservation
	digest                               artifact.Digest
	until                                time.Time
	joined                               sync.WaitGroup
}

func (c *ConnectorObservationChannel) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	c.joined.Wait()
}
