package fleet

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
)

// Signer credentials are limited to one leaf purpose. Issuance does not create
// or activate a registry entry, acknowledge audit or authorize forwarding.
type OwnerCertificateIssuer interface {
	SignOwnerCertificate(context.Context, value.OwnerCertificatePermit, []byte) (value.IssuedOwnerCertificate, error)
}
