package bootstrap

import (
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ownerWorkloadGuard builds the owner pool's protection reader from that plan.
func ownerWorkloadGuard(observer, probe *kube.PermissionClient, pool value.OwnerPool, c contracts.OwnerGuardInputs) (*kube.OwnerWorkloadProtection, error) {
	g := c.WorkloadGuard
	actors := make([]cfg.KubernetesActor, len(g.Administrators))
	for i, a := range g.Administrators {
		actors[i] = cfg.KubernetesActor{Kind: a.Kind, Name: a.Name}
	}
	leases := make([]cfg.OwnerSchedulingLease, len(c.SchedulingLeases))
	for i, l := range c.SchedulingLeases {
		leases[i] = cfg.OwnerSchedulingLease{Lease: l.Lease, ServiceAccount: l.ServiceAccount}
	}
	probes := make([]cfg.OwnerConfigurationProbe, len(c.ConfigurationProbes))
	for i, p := range c.ConfigurationProbes {
		probes[i] = cfg.OwnerConfigurationProbe{ConfigMap: p.ConfigMap, ServiceAccount: p.ServiceAccount}
	}
	var history *cfg.OwnerInitialHistoryProbe
	if p := c.InitialHistoryProbe; p != nil {
		history = &cfg.OwnerInitialHistoryProbe{Namespace: cfg.NamespaceRef{Name: p.Namespace.Name, UID: p.Namespace.UID}, ServiceAccount: p.ServiceAccount.Name, ServiceAccountUID: p.ServiceAccount.UID, Configuration: p.Configuration}
	}
	starts, err := ownerDeploymentStarts(c.APIContextStarts)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	capacity, err := ownerDeploymentCapacityProbe(c.CapacityProbe)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	return kube.NewOwnerWorkloadProtection(observer, probe, cfg.OwnerWorkloadAdministration{Name: g.Name, Deployment: pool.Deployment, DeploymentUID: pool.DeploymentUID, ControlNamespace: control, Administrators: actors, ConfigurationProbes: probes, SchedulingLeases: leases, InitialHistoryProbe: history, APIContextStarts: starts, CapacityProbe: capacity}, kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion})
}

func ownerDeploymentStarts(in *contracts.OwnerDeploymentAPIContextStarts) (*cfg.OwnerAPIContextStarts, error) {
	if in == nil {
		return nil, nil
	}
	if len(validation.IsDNS1123Subdomain(in.CapacityAccount.Name)) != 0 || len(validation.IsDNS1123Subdomain(in.ExecutionAccount.Name)) != 0 {
		return nil, mounts.ErrUnavailable
	}
	out := &cfg.OwnerAPIContextStarts{CapacityAccount: in.CapacityAccount.Name, CapacityAccountUID: in.CapacityAccount.UID, ExecutionAccount: in.ExecutionAccount.Name, ExecutionAccountUID: in.ExecutionAccount.UID, CapacityAudience: in.CapacityAudience}
	if !out.Valid() {
		return nil, mounts.ErrUnavailable
	}
	return out, nil
}

func ownerDeploymentCapacityProbe(in *contracts.OwnerDeploymentCapacityProbe) (*cfg.OwnerCapacityProbe, error) {
	if in == nil {
		return nil, nil
	}
	if len(validation.IsDNS1123Subdomain(in.ServiceAccount.Name)) != 0 {
		return nil, mounts.ErrUnavailable
	}
	out := &cfg.OwnerCapacityProbe{ServiceAccount: in.ServiceAccount.Name, ServiceAccountUID: in.ServiceAccount.UID}
	if !out.Valid() {
		return nil, mounts.ErrUnavailable
	}
	return out, nil
}
