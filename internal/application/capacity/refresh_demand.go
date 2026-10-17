package capacity

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// CapacityRefreshDemand is one ADR-200 demand: admission asked the hub-worker
// to refresh this enrolled workload's binding. It names a workload only; the
// demand lane still performs every observation and SQL check.
type CapacityRefreshDemand struct {
	ClusterID string
	Namespace cfg.NamespaceRef
	Workload  cfg.WorkloadRef
	NotAfter  time.Time
}

func (d CapacityRefreshDemand) Valid(now time.Time) bool {
	return authorization.UUID(d.ClusterID) && identity.Text(d.Namespace.Name, 63) && identity.Text(d.Namespace.UID, 64) &&
		(d.Workload.Kind == "Deployment" || d.Workload.Kind == "StatefulSet" || d.Workload.Kind == "Pod") &&
		identity.Text(d.Workload.Name, 253) && identity.Text(d.Workload.UID, 64) && now.Before(d.NotAfter) && !d.NotAfter.After(now.Add(time.Minute))
}

// CapacityRefreshDemandReader lists active demands for the root, oldest first.
type CapacityRefreshDemandReader interface {
	ReadCapacityRefreshDemands(context.Context) ([]CapacityRefreshDemand, error)
}
