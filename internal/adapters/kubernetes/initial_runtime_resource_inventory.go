package kubernetes

import (
	"context"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// InitialRuntimeResourceInventory is original CREATE provenance for the fixed
// input generators. It is not a current-source observation. Every consumer must
// construct the native guard/source reader and check its actual current values.
// A journal receipt can never stand in for that reader or SQL acceptance.
type InitialRuntimeResourceInventory struct {
	Namespace, FleetSource, OwnerSource                        contracts.WorkerObjectReference
	OwnerDeployment, OwnerAccount, OwnerService                contracts.WorkerObjectReference
	WorkerDeployment, WorkerAccount, LeaderLease               contracts.WorkerObjectReference
	OwnerInputs, WorkerInputs, OwnerProviders, WorkerProviders string
	FleetGuard, OwnerSourceGuard, WorkloadGuard                contracts.OwnerDeploymentGuard
	BridgeAdministration                                       cfg.InitialRuntimeBridgeAdministration
}

func (s *InitialRuntimeResources) ReadInventory(ctx context.Context) (InitialRuntimeResourceInventory, error) {
	v, e := s.Read(ctx)
	if e != nil {
		return InitialRuntimeResourceInventory{}, e
	}
	return s.inventory(v.State)
}

func (s *InitialRuntimeResources) inventory(v contracts.InitialRuntimeResourceState) (InitialRuntimeResourceInventory, error) {
	var zero InitialRuntimeResourceInventory
	if !s.valid(v) || len(v.Objects) != contracts.InitialRuntimeResourceCount || v.Objects[len(v.Objects)-1].Receipt == nil {
		return zero, cfg.ErrUnavailable
	}
	n := s.names
	c := s.initial
	ref := func(i int, name string) contracts.WorkerObjectReference {
		return contracts.WorkerObjectReference{Name: name, UID: v.Objects[i].Receipt.UID}
	}
	guard := func(i int, name string) contracts.OwnerDeploymentGuard {
		p, b := v.Objects[i].Receipt, v.Objects[i+1].Receipt
		return contracts.OwnerDeploymentGuard{Name: name, PolicyUID: p.UID, PolicyGeneration: p.Generation, BindingUID: b.UID, BindingResourceVersion: b.ResourceVersion, Administrators: append([]contracts.OwnerDeploymentActor(nil), s.preparer.plan.Administrators...)}
	}
	out := InitialRuntimeResourceInventory{Namespace: c.Namespace, FleetSource: c.FleetSource, OwnerSource: ref(14, n.OwnerSource), OwnerDeployment: ref(10, n.Owner), OwnerAccount: ref(0, n.Owner), OwnerService: ref(12, n.Owner), WorkerDeployment: ref(11, n.Worker), WorkerAccount: ref(1, n.Worker), LeaderLease: ref(13, n.Lease), OwnerInputs: n.OwnerInputs, WorkerInputs: n.WorkerInputs, OwnerProviders: n.OwnerProviders, WorkerProviders: n.WorkerProviders, FleetGuard: c.FleetGuard, OwnerSourceGuard: guard(15, n.OwnerSourceGuard), WorkloadGuard: guard(17, n.WorkloadGuard)}
	a, e := s.preparer.runtimeBridgeAdministration(c, s.ownerLayout, out.OwnerDeployment, out.OwnerAccount, out.WorkerAccount)
	if e != nil {
		return zero, e
	}
	out.BridgeAdministration = a
	return out, nil
}

// runtimeBridgeAdministration derives the guard bridge's administration from
// the original installer input, the layout and three journal receipts. A
// fresh process after the bridge recomputes it the same way (ADR-187).
func (p *InitialPreparer) runtimeBridgeAdministration(c contracts.InitialInstaller, ownerLayout string, ownerDeployment, ownerAccount, workerAccount contracts.WorkerObjectReference) (cfg.InitialRuntimeBridgeAdministration, error) {
	var zero cfg.InitialRuntimeBridgeAdministration
	n := runtimeResourceNames(c.InstallationID)
	digest, e := initialPreparationDigest(c.PodSpecDigest)
	if e != nil {
		return zero, e
	}
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	admins := preparerAdministration(p.plan).Administrators
	h := p.plan.HistoryProbe
	if h == nil {
		return zero, cfg.ErrChanged
	}
	owner := cfg.OwnerWorkloadAdministration{Name: n.WorkloadGuard, Deployment: n.Owner, DeploymentUID: ownerDeployment.UID, ControlNamespace: control, Administrators: admins, ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: c.FleetSource.Name, ServiceAccount: n.Worker}, {ConfigMap: n.OwnerSource, ServiceAccount: n.Worker}}, SchedulingLeases: []cfg.OwnerSchedulingLease{{Lease: n.Lease, ServiceAccount: n.Worker}}, InitialHistoryProbe: &cfg.OwnerInitialHistoryProbe{Namespace: cfg.NamespaceRef{Name: p.plan.BootstrapNamespace.Name, UID: p.plan.BootstrapNamespace.UID}, ServiceAccount: h.Name, ServiceAccountUID: h.UID, Configuration: c.Configuration}}
	if ownerLayout == contracts.OwnerInstalledLayout || ownerLayout == contracts.OwnerProviderInstalledLayout {
		owner.CapacityProbe = &cfg.OwnerCapacityProbe{ServiceAccount: workerAccount.Name, ServiceAccountUID: workerAccount.UID}
		owner.ConfigurationProbes = append(owner.ConfigurationProbes, cfg.OwnerConfigurationProbe{ConfigMap: installedProcessingSource(c.InstallationID), ServiceAccount: workerAccount.Name})
	}
	if ownerLayout == contracts.OwnerProviderInstalledLayout {
		owner.ConfigurationProbes = append(owner.ConfigurationProbes, ownerPublicSourceProbes(c.InstallationID, n.Owner)...)
	}
	out := cfg.InitialRuntimeBridgeAdministration{
		Initial: cfg.InitialWorkloadAdministration{Handover: true, Name: c.WorkloadGuard.Name, Configuration: c.Configuration, Witness: c.Witness.Name, FleetSource: c.FleetSource.Name, ControlNamespace: control, PodName: c.Pod.Name, PodUID: c.Pod.UID, WriterAccount: c.WriterAccount.Name, WriterAccountUID: c.WriterAccount.UID, ProbeAccount: c.ProbeAccount.Name, ProbeAccountUID: c.ProbeAccount.UID, PodSpecDigest: digest, Administrators: append([]cfg.KubernetesActor(nil), admins...)},
		Owner:   owner, Credentials: p.plan.Workload.Credentials,
		OwnerProbe:   cfg.InitialRuntimeProbe{ServiceAccount: n.Owner, ServiceAccountUID: ownerAccount.UID},
		SourceProbes: []cfg.InitialRuntimeSourceProbe{{ConfigMap: c.FleetSource.Name, ServiceAccount: n.Worker, ServiceAccountUID: workerAccount.UID}, {ConfigMap: n.OwnerSource, ServiceAccount: n.Worker, ServiceAccountUID: workerAccount.UID}},
	}
	if owner.CapacityProbe != nil {
		out.SourceProbes = append(out.SourceProbes, cfg.InitialRuntimeSourceProbe{ConfigMap: installedProcessingSource(c.InstallationID), ServiceAccount: workerAccount.Name, ServiceAccountUID: workerAccount.UID})
	}
	if ownerLayout == contracts.OwnerProviderInstalledLayout {
		// ADR-203: the publisher's catalog pair (ownerPublicSourceProbes).
		out.RuntimeProbeAccounts = []string{contracts.PublisherName(c.InstallationID)}
	}
	if !out.Valid() {
		return zero, cfg.ErrChanged
	}
	return out, nil
}
