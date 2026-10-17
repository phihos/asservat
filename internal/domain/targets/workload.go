package targets

import (
	"errors"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

var (
	ErrLimit           = errors.New("target candidate limit exceeded")
	ErrNoScheduledPods = errors.New("workload has no scheduled pod")
	ErrNoEligiblePods  = errors.New("workload has no eligible pod")
)

// WorkloadRequest names a public target without supplying trusted UIDs, node
// facts or an API endpoint. It is input to private observation, not permission
// to disclose any resulting metadata or execute collection.
type WorkloadRequest struct {
	ClusterID, Namespace, Kind, Name string
}

func (r WorkloadRequest) Valid() bool {
	return authorization.UUID(r.ClusterID) && identity.Text(r.Namespace, 63) && identity.Text(r.Name, 253) && (r.Kind == "Deployment" || r.Kind == "StatefulSet" || r.Kind == "Pod")
}
