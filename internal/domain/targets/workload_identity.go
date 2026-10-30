package targets

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// WorkloadIdentityResolution observes a named permission/storage root. It is
// not a selected Pod, source lease, collection permit or evidence authority.
type WorkloadIdentityResolution struct {
	Reference              WorkloadRequest
	ClusterID              string
	Namespace              configuration.NamespaceRef
	Workload               configuration.WorkloadRef
	ObservedAt, FreshUntil time.Time
}

func (r WorkloadIdentityResolution) Target() authorization.WorkloadTarget {
	return authorization.WorkloadTarget{ClusterID: r.ClusterID, NamespaceUID: r.Namespace.UID, WorkloadUID: r.Workload.UID}
}
func (r WorkloadIdentityResolution) Valid(now time.Time) bool {
	return r.Reference.Valid() && r.Reference.ClusterID == r.ClusterID && r.Reference.Namespace == r.Namespace.Name && (r.Reference.Kind == "Pod" || r.Reference.Kind == r.Workload.Kind && r.Reference.Name == r.Workload.Name) && r.Target().Valid() && identity.Text(r.Namespace.Name, 63) && identity.Text(r.Workload.Name, 253) && (r.Workload.Kind == "Deployment" || r.Workload.Kind == "StatefulSet" || r.Workload.Kind == "Pod") && identity.Fresh(r.ObservedAt, r.FreshUntil, now, 5*time.Second)
}
