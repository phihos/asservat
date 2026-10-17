package fleet

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"strings"
	"time"
)

// ConnectorDeployment is independently protected installation configuration.
// ServingSlots permits a bounded rolling overlap. RetainedProcesses counts all
// pending, uncertain and replaced children until separately verified retirement.
type ConnectorDeployment struct {
	Namespace, NamespaceUID         string
	ServiceAccount, AccountUID      string
	Deployment, DeploymentUID       string
	ServingSlots, RetainedProcesses int
}

func (p ConnectorDeployment) Valid() bool {
	return !strings.Contains(p.Namespace, ".") && connectorDNSName(p.Namespace) && len(p.Namespace) <= 63 && authorization.UUID(p.NamespaceUID) && connectorDNSName(p.ServiceAccount) && authorization.UUID(p.AccountUID) && connectorDNSName(p.Deployment) && authorization.UUID(p.DeploymentUID) && p.ServingSlots >= 1 && p.ServingSlots <= 16 && p.RetainedProcesses >= p.ServingSlots+1 && p.RetainedProcesses <= 256
}

// ConnectorProcessIdentity is not a new logical peer/account. The Pod and epoch
// distinguish process keys; only the protected SQL transition admits one pending
// replacement per Pod and retires its prior serving epoch atomically.
type ConnectorProcessIdentity struct {
	Binding              PeerBinding
	PodUID, ProcessEpoch string
}

func (p ConnectorProcessIdentity) Valid() bool {
	return p.Binding.Valid() && p.Binding.Role == ConnectorPeer && authorization.UUID(p.PodUID) && authorization.UUID(p.ProcessEpoch)
}

type ConnectorProcessRequest struct {
	Process                    ConnectorProcessIdentity
	ClientCSRDER, ServerCSRDER []byte
}

func (r ConnectorProcessRequest) Valid() bool {
	return r.Process.Valid() && len(r.ClientCSRDER) >= 32 && len(r.ClientCSRDER) <= 8192 && len(r.ServerCSRDER) >= 32 && len(r.ServerCSRDER) <= 8192
}

// A live proof is an observation, not certificate or process-registration
// authority. A Pod token proves the Pod, not process uniqueness. SQL admission
// supplies the latter bound without reusing or resetting the logical account.
type ConnectorProcessProof struct {
	Process                                       ConnectorProcessIdentity
	Configuration                                 ConnectorCredentialObservation
	Pod, ReplicaSet, ReplicaSetUID                string
	ClientKeyDigest, ServerKeyDigest              artifact.Digest
	TokenDigest, WorkloadDigest, ProtectionDigest artifact.Digest
	ObservedAt, FreshUntil                        time.Time
}

func (p ConnectorProcessProof) Valid(now time.Time) bool {
	c := p.Configuration
	return p.Process.Valid() && c.Valid(now) && c.Profile.Deployment.Valid() && p.Process.Binding == c.Profile.Binding && connectorDNSName(p.Pod) && connectorDNSName(p.ReplicaSet) && authorization.UUID(p.ReplicaSetUID) && p.ClientKeyDigest != (artifact.Digest{}) && p.ServerKeyDigest != (artifact.Digest{}) && p.ClientKeyDigest != p.ServerKeyDigest && p.TokenDigest != (artifact.Digest{}) && p.WorkloadDigest != (artifact.Digest{}) && p.ProtectionDigest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second) && !p.FreshUntil.After(c.FreshUntil)
}
func (p ConnectorProcessProof) Clone() ConnectorProcessProof {
	p.Configuration.Profile = p.Configuration.Profile.Clone()
	return p
}
func (p ConnectorProcessProof) WellFormed() bool {
	start := p.ObservedAt
	if p.Configuration.ObservedAt.After(start) {
		start = p.Configuration.ObservedAt
	}
	return p.Valid(start)
}
