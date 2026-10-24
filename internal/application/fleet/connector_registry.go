package fleet

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"time"
)

// ConnectorLeafRegistration keeps serverAuth distinct from client peer identity.
// This is a current registry observation, never a substitute TLS handshake.
type ConnectorLeafRegistration struct {
	Certificate            value.ConnectorCredentialCertificate
	Process                value.ConnectorProcessIdentity
	Revision               identity.Revision
	ObservedAt, FreshUntil time.Time
}

func (r ConnectorLeafRegistration) Valid(now time.Time) bool {
	return r.Certificate.Valid(now) && r.Process.Valid() && r.Certificate.Binding == r.Process.Binding && r.Revision.Valid() && identity.Fresh(r.ObservedAt, r.FreshUntil, now, 5*time.Second) && !r.FreshUntil.After(r.Certificate.NotAfter)
}

type ConnectorLeafRegistry interface {
	ConnectorLeafRegistration(context.Context, value.ConnectorCredentialCertificate) (ConnectorLeafRegistration, error)
}

// ConnectorLeafRegistryAt is an optional read-only registration composition
// inside the executor's original source bracket. The caller owns a complete
// opening source proof and must perform its complete closing proof after this
// lookup before using the result. The registry retains current SQL/recovery
// checks and the original source/caller bounds; it cannot renew the source or
// use it for enrollment, signing, acceptance or a later conversation.
type ConnectorLeafRegistryAt interface {
	ConnectorLeafRegistrationAt(context.Context, value.ConnectorCredentialCertificate, value.ConnectorIdentitySource) (ConnectorLeafRegistration, error)
}
