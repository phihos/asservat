package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Preserve every existing guard branch when joining immutable owner inputs to
// the original bridge. The carrier cannot silently supply a partial policy.
func capacityLocalOwnerAdministration(o contracts.OwnerDeployment, p contracts.OwnerConfiguration) cfg.OwnerWorkloadAdministration {
	g := o.WorkloadGuard
	out := cfg.OwnerWorkloadAdministration{Name: g.Name, Deployment: p.Deployment.Name, DeploymentUID: p.Deployment.UID, ControlNamespace: cfg.NamespaceRef{Name: o.Namespace.Name, UID: o.Namespace.UID}}
	for _, a := range g.Administrators {
		out.Administrators = append(out.Administrators, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
	}
	for _, v := range o.ConfigurationProbes {
		out.ConfigurationProbes = append(out.ConfigurationProbes, cfg.OwnerConfigurationProbe{ConfigMap: v.ConfigMap, ServiceAccount: v.ServiceAccount})
	}
	for _, v := range o.SchedulingLeases {
		out.SchedulingLeases = append(out.SchedulingLeases, cfg.OwnerSchedulingLease{Lease: v.Lease, ServiceAccount: v.ServiceAccount})
	}
	if h := o.InitialHistoryProbe; h != nil {
		out.InitialHistoryProbe = &cfg.OwnerInitialHistoryProbe{Namespace: cfg.NamespaceRef{Name: h.Namespace.Name, UID: h.Namespace.UID}, ServiceAccount: h.ServiceAccount.Name, ServiceAccountUID: h.ServiceAccount.UID, Configuration: h.Configuration}
	}
	if p := o.CapacityProbe; p != nil {
		out.CapacityProbe = &cfg.OwnerCapacityProbe{ServiceAccount: p.ServiceAccount.Name, ServiceAccountUID: p.ServiceAccount.UID}
	}
	if a := o.APIContextStarts; a != nil {
		out.APIContextStarts = &cfg.OwnerAPIContextStarts{CapacityAccount: a.CapacityAccount.Name, CapacityAccountUID: a.CapacityAccount.UID, ExecutionAccount: a.ExecutionAccount.Name, ExecutionAccountUID: a.ExecutionAccount.UID, CapacityAudience: a.CapacityAudience}
	}
	return out
}

// Concrete protected profile constructor. It retains all original guard
// branches; the current guard checks remain independent of the SQL registry.
func NewCapacityLocalOwnerProtection(observer, probe *PermissionClient, c contracts.CapacityDeployment, m contracts.CapacityCredentialManifest) (*OwnerWorkloadProtection, error) {
	if _, err := CapacityLocalOwnerBinding(c, m); err != nil {
		return nil, err
	}
	g := c.LocalOwner.Deployment.WorkloadGuard
	return NewOwnerWorkloadProtection(observer, probe, capacityLocalOwnerAdministration(c.LocalOwner.Deployment, c.LocalOwner.Pool), GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion})
}
