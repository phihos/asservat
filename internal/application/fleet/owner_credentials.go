package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// OwnerCredentialEnrollment is the audited enrollment operation, not a raw CA
// signer. The private composition supplies its proof, ledger and audit roles.
type OwnerCredentialEnrollment interface {
	Enroll(context.Context, value.OwnerEnrollmentRequest) (value.IssuedOwnerCertificate, error)
}

type OwnerCredentialClient interface {
	Enroll(context.Context) error
	Certificate() (value.OwnerCertificate, error)
	Close()
}
