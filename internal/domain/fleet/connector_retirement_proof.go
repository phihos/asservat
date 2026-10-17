package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorRetirementProof identifies the actual live actor for one protected
// retirement audit. It is not process enrollment, credential, serving, or backing
// promotion authority. Ordinary proof validation rejects this suspended source.
// Retirement must be acknowledged before workload teardown; later historical
// cleanup uses its immutable accepted result, not a fabricated live actor.
type ConnectorRetirementProof ConnectorProcessProof

func (p ConnectorRetirementProof) Valid(now time.Time) bool {
	c := p.Configuration
	return p.Process.Valid() && c.Backing.Valid() && c.Profile.Valid() && c.Profile.Suspended && c.Profile.Retiring && identity.Fresh(c.ObservedAt, c.FreshUntil, now, 5*time.Second) && c.Profile.Deployment.Valid() && p.Process.Binding == c.Profile.Binding && connectorDNSName(p.Pod) && connectorDNSName(p.ReplicaSet) && authorization.UUID(p.ReplicaSetUID) && p.ClientKeyDigest != (artifact.Digest{}) && p.ServerKeyDigest != (artifact.Digest{}) && p.ClientKeyDigest != p.ServerKeyDigest && p.TokenDigest != (artifact.Digest{}) && p.WorkloadDigest != (artifact.Digest{}) && p.ProtectionDigest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second) && !p.FreshUntil.After(c.FreshUntil)
}

func (p ConnectorRetirementProof) Clone() ConnectorRetirementProof {
	p.Configuration.Profile = p.Configuration.Profile.Clone()
	return p
}

func (p ConnectorRetirementProof) WellFormed() bool {
	start := p.ObservedAt
	if p.Configuration.ObservedAt.After(start) {
		start = p.Configuration.ObservedAt
	}
	return p.Valid(start)
}
