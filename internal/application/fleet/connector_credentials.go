package fleet

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ConnectorBootstrapReference is protected installation delivery, not a new
// issuance permit. SQL independently checks the original reviewed bootstrap,
// secret digest, original expiry and exact key. No constructor renews them.
type ConnectorBootstrapReference struct {
	ID                  string
	Binding             value.PeerBinding
	SecretDigest        artifact.Digest
	NotBefore, NotAfter time.Time
}

func (r ConnectorBootstrapReference) Valid(now time.Time) bool {
	return authorization.UUID(r.ID) && r.Binding.Valid() && r.Binding.Role == value.ConnectorPeer && r.SecretDigest != (artifact.Digest{}) && !r.NotBefore.IsZero() && !now.Before(r.NotBefore) && now.Before(r.NotAfter) && r.NotAfter.After(r.NotBefore) && !r.NotAfter.After(r.NotBefore.Add(5*time.Minute))
}

// The existing audited coordinator implements this port. A raw PKI signer does
// not: returning an issued-but-inactive certificate cannot satisfy enrollment.
type ConnectorCredentialEnrollment interface {
	Enroll(context.Context, value.EnrollmentClaim, []byte) (value.IssuedCertificate, error)
}

// This historical read independently pins the original claim/key/expiry. It is
// never current peer authority; the consumer separately checks PeerRegistry.
type ConnectorCredentialClaims interface {
	ReadEnrollmentClaim(context.Context, string, string) (audit.EnrollmentClaim, error)
}
