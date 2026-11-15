package fleet

import (
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

// ConnectorDeployment names the Helm-rendered connector workload. Objects are
// matched by name under RBAC; the platform keeps UIDs (helm-native plan).
// ServingSlots permits a bounded rolling overlap. RetainedProcesses counts all
// pending, uncertain and replaced children until separately verified retirement.
type ConnectorDeployment struct {
	Namespace                       string
	ServiceAccount                  string
	Deployment                      string
	ServingSlots, RetainedProcesses int
}

func (p ConnectorDeployment) Valid() bool {
	return !strings.Contains(p.Namespace, ".") && connectorDNSName(p.Namespace) && len(p.Namespace) <= 63 && connectorDNSName(p.ServiceAccount) && connectorDNSName(p.Deployment) && p.ServingSlots >= 1 && p.ServingSlots <= 16 && p.RetainedProcesses >= p.ServingSlots+1 && p.RetainedProcesses <= 256
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
