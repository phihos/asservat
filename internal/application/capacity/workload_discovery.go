package capacity

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

const CapacityDiscoveryPageSize = 64

// List pages are candidate discovery only. Their continuation is an opaque
// process-local cursor, never a source checkpoint, absence proof or permit.
// The reconciler re-reads exact namespace/workload identities before backing.
type CapacityNamespacePage struct {
	ResourceVersion, Continue string
	Namespaces                []cfg.NamespaceRef
}
type CapacityWorkloadPage struct {
	ResourceVersion, Continue string
	Workloads                 []cfg.WorkloadRef
}
type CapacityWorkloadObservation struct {
	Namespace               cfg.NamespaceMetadata
	Workload                cfg.WorkloadRef
	WorkloadResourceVersion string
	ObservedAt, FreshUntil  time.Time
}

func (v CapacityWorkloadObservation) Valid(now time.Time) bool {
	return authorization.UUID(v.Namespace.ClusterID) && !v.Namespace.Deleting && identity.Text(v.Namespace.Namespace.Name, 63) && identity.Text(v.Namespace.Namespace.UID, 64) && identity.Text(v.Namespace.ResourceVersion, 128) && identity.Text(v.Workload.Name, 253) && identity.Text(v.Workload.UID, 64) && identity.Text(v.WorkloadResourceVersion, 128) && (v.Workload.Kind == "Deployment" || v.Workload.Kind == "StatefulSet" || v.Workload.Kind == "Pod") && identity.Fresh(v.ObservedAt, v.FreshUntil, now, CapacitySourceInterval) && identity.Fresh(v.Namespace.ObservedAt, v.Namespace.FreshUntil, now, CapacitySourceInterval) && !v.FreshUntil.After(v.Namespace.FreshUntil)
}

type CapacityWorkloadReader interface {
	DiscoverCapacityNamespaces(context.Context, string) (CapacityNamespacePage, error)
	DiscoverCapacityWorkloads(context.Context, cfg.NamespaceRef, string, string) (CapacityWorkloadPage, error)
	ReadCapacityWorkload(context.Context, cfg.NamespaceRef, cfg.WorkloadRef, []string) (CapacityWorkloadObservation, error)
}
