package mtls

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

// OwnerObservationClient owns only finite own-server proof requests. The fixed
// protected address is a dial hint; TLS uses the independently pinned Service
// name, original candidate set and current registry. Results do not authorize
// another connection or a metadata/effect request.
type OwnerObservationClient struct {
	root            context.Context
	cancel          context.CancelFunc
	pin             value.OwnerObservationPin
	address, name   string
	roots           *x509.CertPool
	verifier        *OwnerPeerVerifier
	connector       *ConnectorProcessCredentials
	candidates      *app.OwnerObservationCandidateSelection
	registry        app.OwnerCertificateRegistry
	now             func() time.Time
	mu              sync.Mutex
	closed          bool
	active, maximum int
	joined          sync.WaitGroup
}
