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
