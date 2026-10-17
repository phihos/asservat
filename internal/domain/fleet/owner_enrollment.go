package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerEnrollmentRequest carries no asserted Kubernetes account, endpoint or
// issuer roots. The CSR must separately prove possession of an identity-free key.
type OwnerEnrollmentRequest struct {
	Binding OwnerBinding
	Usage   string
	CSRDER  []byte
}

func (r OwnerEnrollmentRequest) Valid() bool {
	return r.Binding.Valid() && (r.Usage == "server" || r.Usage == "client") && len(r.CSRDER) >= 32 && len(r.CSRDER) <= 8192
}

// OwnerEnrollmentProof is a short observation, not a signing permit or an
// activated peer. ProcessEpoch becomes unique only through durable enrollment;
// a Pod token attests a Pod, not one particular process running inside it.
type OwnerEnrollmentProof struct {
	Binding                                                        OwnerBinding
	Usage                                                          string
	Configuration                                                  OwnerConfigurationObservation
	Pod, ReplicaSet, ReplicaSetUID                                 string
	PublicKeyDigest, TokenDigest, WorkloadDigest, ProtectionDigest artifact.Digest
	ObservedAt, FreshUntil                                         time.Time
}

func (p OwnerEnrollmentProof) Valid(now time.Time) bool {
	c := p.Configuration.Configuration
	return p.Binding.Valid() && (p.Usage == "server" || p.Usage == "client") && p.Configuration.Valid(now) && !c.Suspended && p.Binding.InstallationID == c.Pool.InstallationID && p.Binding.ClusterID == c.Pool.ClusterID && p.Binding.IssuerEpoch == c.Pool.IssuerEpoch && identity.Text(p.Pod, 253) && identity.Text(p.ReplicaSet, 253) && authorization.UUID(p.ReplicaSetUID) && p.PublicKeyDigest != (artifact.Digest{}) && p.TokenDigest != (artifact.Digest{}) && p.WorkloadDigest != (artifact.Digest{}) && p.ProtectionDigest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second) && !p.FreshUntil.After(p.Configuration.FreshUntil)
}

func (p OwnerEnrollmentProof) Clone() OwnerEnrollmentProof {
	p.Configuration.Configuration = p.Configuration.Configuration.Clone()
	return p
}

// WellFormed validates that the original observation intervals overlap. A
// configuration read can finish after proof collection starts, or be cached
// from before it. Neither case changes the original proof deadline. This is
// structural validation only; effects must still call Valid with current time.
func (p OwnerEnrollmentProof) WellFormed() bool {
	first := p.ObservedAt
	if p.Configuration.ObservedAt.After(first) {
		first = p.Configuration.ObservedAt
	}
	return p.Valid(first)
}
