package fleet

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// Current protection is bound to the independently pinned private workload.
// Its digest is distinct from configuration-source protection and enrollment.
type OwnerProtection struct {
	Pool                   OwnerPool
	Digest                 artifact.Digest
	ObservedAt, FreshUntil time.Time
}

func (p OwnerProtection) Valid(now time.Time) bool {
	return p.Pool.Valid() && p.Digest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second)
}

// AuthenticatedOwner is finite peer identity, never a request locator, a human
// session, an evidence permission or authority to take over another request.
type AuthenticatedOwner struct {
	Certificate            OwnerCertificate
	EnrollmentID           string
	Pool                   OwnerPool
	Pod, ReplicaSetUID     string
	ConfigurationRevision  identity.Revision
	ProtectionDigest       artifact.Digest
	VerifiedAt, ValidUntil time.Time
}

// OwnerServingReuse bounds how long the hub process may reuse its own local
// serving observation (route, registration, protection), like its
// self-protection proof (installed native89). A remote peer is still
// authenticated per request with a five-second observation.
const OwnerServingReuse = 30 * time.Second

func (o AuthenticatedOwner) Valid(now time.Time) bool {
	b := o.Certificate.Binding
	return o.Certificate.Valid(now) && authorization.UUID(o.EnrollmentID) && o.Pool.Valid() && b.InstallationID == o.Pool.InstallationID && b.ClusterID == o.Pool.ClusterID && b.IssuerEpoch == o.Pool.IssuerEpoch && identity.Text(o.Pod, 253) && authorization.UUID(o.ReplicaSetUID) && o.ConfigurationRevision.Valid() && o.ProtectionDigest != (artifact.Digest{}) && identity.Fresh(o.VerifiedAt, o.ValidUntil, now, OwnerServingReuse) && !o.ValidUntil.After(o.Certificate.NotAfter)
}
