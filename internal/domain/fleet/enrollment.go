package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// EnrollmentClaim contains a hash of a random 256-bit bootstrap secret and an
// independently checked CSR key. Neither field is a peer execution credential.
type EnrollmentClaim struct {
	InstallationID, BootstrapID   string
	SecretDigest, PublicKeyDigest artifact.Digest
}

func (c EnrollmentClaim) Valid() bool {
	return authorization.UUID(c.InstallationID) && authorization.UUID(c.BootstrapID) && c.SecretDigest != (artifact.Digest{}) && c.PublicKeyDigest != (artifact.Digest{})
}

type Enrollment struct {
	BootstrapID         string
	Binding             PeerBinding
	PublicKeyDigest     artifact.Digest
	ClaimedAt, NotAfter time.Time
	Replay              bool
}

// CertificateIssuePermit is supplied by the current audited enrollment
// coordinator. Constructors and caller-created values confer no authority.
type CertificateIssuePermit struct {
	Enrollment            Enrollment
	ClaimAuditDigest      artifact.Digest
	TrustRevision         identity.Revision
	CheckedAt, ValidUntil time.Time
}

func (p CertificateIssuePermit) Valid(now time.Time) bool {
	e := p.Enrollment
	return authorization.UUID(e.BootstrapID) && e.Binding.Valid() && e.Binding.Role == ConnectorPeer && e.PublicKeyDigest != (artifact.Digest{}) && !e.ClaimedAt.IsZero() && !e.ClaimedAt.After(now) && now.Before(e.NotAfter) && e.NotAfter.After(e.ClaimedAt) && !e.NotAfter.After(e.ClaimedAt.Add(5*time.Minute)) && p.ClaimAuditDigest != (artifact.Digest{}) && p.TrustRevision.Valid() && identity.Fresh(p.CheckedAt, p.ValidUntil, now, 5*time.Second) && !p.ValidUntil.After(e.NotAfter)
}
func (p CertificateIssuePermit) CertificateNotAfter() time.Time {
	return p.Enrollment.ClaimedAt.Add(30 * time.Minute).UTC().Truncate(time.Second)
}

type IssuedCertificate struct {
	Certificate PeerCertificate
	DER         []byte
	ChainDER    [][]byte
}
