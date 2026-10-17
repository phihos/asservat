package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// ClusterObservationCallerPin is protected installer input for the one local
// HWORK observation caller. Its cluster is the caller's control cluster, not the
// regional target. It grants no SQL, capacity-write or execution permission.
type ClusterObservationCallerPin struct {
	RootID, InstallationID, ClusterID             string
	Namespace                                     cfg.NamespaceRef
	Account, AccountUID                           string
	Deployment, DeploymentUID                     string
	TemplateDigest, ImageDigest, ProtectionDigest artifact.Digest
}

func (p ClusterObservationCallerPin) Valid() bool {
	for _, id := range []string{p.RootID, p.InstallationID, p.ClusterID, p.Namespace.UID, p.AccountUID, p.DeploymentUID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return identity.Text(p.Namespace.Name, 63) && identity.Text(p.Account, 253) && identity.Text(p.Deployment, 253) && p.TemplateDigest != (artifact.Digest{}) && p.ImageDigest != (artifact.Digest{}) && p.ProtectionDigest != (artifact.Digest{})
}

func ClusterObservationAudience(installation string) string {
	return "https://asservat." + installation + "/cluster-observation"
}

// ClusterObservationCaller is transient exact local workload evidence. Only
// the installed Kubernetes adapter produces it in the runtime composition.
// Neither the Pod UID hint nor a decoded token constructs this observation.
type ClusterObservationCaller struct {
	Pin                                    ClusterObservationCallerPin
	Pod, PodUID, ReplicaSet, ReplicaSetUID string
	WorkloadDigest                         artifact.Digest
	ObservedAt, FreshUntil                 time.Time
}

func (p ClusterObservationCaller) Valid(now time.Time) bool {
	return p.Pin.Valid() && identity.Text(p.Pod, 253) && authorization.UUID(p.PodUID) && identity.Text(p.ReplicaSet, 253) && authorization.UUID(p.ReplicaSetUID) && p.WorkloadDigest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second)
}

func (p ClusterObservationCaller) Matches(r ClusterObservationRequest, now time.Time) bool {
	return r.Valid(now) && p.Valid(now) && p.Pin.RootID == r.RootID && !p.ObservedAt.Before(r.RequestedAt) && !p.FreshUntil.After(r.NotAfter)
}

func (p ClusterObservationCaller) SameWorkload(other ClusterObservationCaller) bool {
	return p.Pin == other.Pin && p.Pod == other.Pod && p.PodUID == other.PodUID && p.ReplicaSet == other.ReplicaSet && p.ReplicaSetUID == other.ReplicaSetUID && p.WorkloadDigest == other.WorkloadDigest
}
