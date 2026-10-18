package bootstrap

import (
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// validOwnerGuard checks the installed owner guard plan that hub-api and the
// federation's owner reads (ADR-172) share.
func validOwnerGuard(c contracts.OwnerGuardInputs) bool {
	if !authorization.UUID(c.Namespace.UID) || !authorization.UUID(c.ConfigurationUID) || !identity.Text(c.Namespace.Name, 63) || !ownerEndpoint(c.Kubernetes.Endpoint) {
		return false
	}
	if _, _, err := mtls.OwnerTrustRoots(c.Kubernetes.Roots, time.Now()); err != nil {
		return false
	}
	g := c.WorkloadGuard
	if p := c.InitialHistoryProbe; p != nil {
		if !authorization.UUID(p.Namespace.UID) || !authorization.UUID(p.ServiceAccount.UID) || p.Namespace.Name == c.Namespace.Name || p.Namespace.UID == c.Namespace.UID || len(validation.IsDNS1123Label(p.Namespace.Name)) != 0 || len(validation.IsDNS1123Subdomain(p.ServiceAccount.Name)) != 0 || len(validation.IsDNS1123Subdomain(p.Configuration)) != 0 {
			return false
		}
	}
	if c.SchedulingLeases == nil || len(c.SchedulingLeases) > 4 {
		return false
	}
	leases := map[contracts.OwnerSchedulingLease]bool{}
	for _, lease := range c.SchedulingLeases {
		if len(validation.IsDNS1123Subdomain(lease.Lease)) != 0 || len(validation.IsDNS1123Subdomain(lease.ServiceAccount)) != 0 || leases[lease] {
			return false
		}
		leases[lease] = true
	}
	if c.ConfigurationProbes == nil || len(c.ConfigurationProbes) > cfg.MaxOwnerConfigurationProbes {
		return false
	}
	probes := map[contracts.OwnerConfigurationProbe]bool{}
	for _, probe := range c.ConfigurationProbes {
		if len(validation.IsDNS1123Subdomain(probe.ConfigMap)) != 0 || len(validation.IsDNS1123Subdomain(probe.ServiceAccount)) != 0 || probes[probe] {
			return false
		}
		probes[probe] = true
	}
	if !identity.Text(g.Name, 253) || !authorization.UUID(g.PolicyUID) || !authorization.UUID(g.BindingUID) || !identity.Text(g.BindingResourceVersion, 128) || g.PolicyGeneration < 1 || g.PolicyGeneration >= 1<<53 || len(g.Administrators) < 1 || len(g.Administrators) > 32 {
		return false
	}
	seen := map[contracts.OwnerDeploymentActor]bool{}
	for _, a := range g.Administrators {
		if (a.Kind != "User" && a.Kind != "Group") || !identity.Text(a.Name, 256) || seen[a] {
			return false
		}
		seen[a] = true
	}
	if _, err := ownerDeploymentCapacityProbe(c.CapacityProbe); err != nil {
		return false
	}
	if _, err := ownerDeploymentStarts(c.APIContextStarts); err != nil {
		return false
	}
	return true
}

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
