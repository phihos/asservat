package fleet

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorLeafRegistration keeps serverAuth distinct from client peer identity.
// This is a current registry observation, never a substitute TLS handshake.
type ConnectorLeafRegistration struct {
	Certificate            value.ConnectorCredentialCertificate
	Process                value.ConnectorProcessIdentity
	Revision               identity.Revision
	ObservedAt, FreshUntil time.Time
}

type ConnectorLeafRegistry interface {
	ConnectorLeafRegistration(context.Context, value.ConnectorCredentialCertificate) (ConnectorLeafRegistration, error)
}

// ConnectorLeafRegistryAt is an optional read-only registration composition
// inside the executor's original source bracket. The caller owns a complete
// opening source proof and must perform its complete closing proof after this
// lookup before using the result. The registry retains current SQL
// checks and the original source/caller bounds; it cannot renew the source or
// use it for enrollment, signing, acceptance or a later conversation.
type ConnectorLeafRegistryAt interface {
	ConnectorLeafRegistrationAt(context.Context, value.ConnectorCredentialCertificate, value.ConnectorIdentitySource) (ConnectorLeafRegistration, error)
}
