package kubernetes

import (
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func publicRuntimeWorkerBindingValid(in contracts.PublicRuntimeRoles) bool {
	w := in.Worker
	prefix := strings.ReplaceAll(in.InstallationID, "-", "")
	names := runtimeResourceNames(in.InstallationID)
	if !configurationWorkerProviderBound(in) || !authorization.UUID(w.ResourceSetupID) || !authorization.UUID(w.ConfigurationSetupID) || !preparationDigestValid(w.ResourceBinding) || !installationRefValid(w.FleetGuardName, w.Resources.UID) || w.Resources.Name != "asservat-runtime-resources-"+prefix || !authorization.UUID(w.Resources.UID) || w.ConfigurationRoot.Name != "asservat-configuration-roles-"+prefix || !authorization.UUID(w.ConfigurationRoot.UID) || w.Resources.UID == w.ConfigurationRoot.UID {
		return false
	}
	c := w.Configuration
	if c.Format != contracts.ConfigurationRuntimeRolesFormat || c.InstallationID != in.InstallationID || c.InitialClaimID != in.InitialClaimID || c.ClusterID != in.ClusterID || c.Namespace != in.Namespace || c.Deployment != w.Deployment.Reference || c.ServiceAccount != w.Account.Reference || c.OwnerSource.UID != in.OwnerConfigurationUID || c.OwnerSource.Name != names.OwnerSource || !installationRefValid(c.FleetSource.Name, c.FleetSource.UID) || !preparationDigestValid(c.LayoutDigest) {
		return false
	}
	seen := map[string]bool{w.Resources.UID: true, w.ConfigurationRoot.UID: true}
	for _, entry := range []struct {
		value contracts.PublicRuntimeWorkerObject
		name  string
	}{{w.Deployment, names.Worker}, {w.Account, names.Worker}, {w.Lease, names.Lease}} {
		v := entry.value
		if v.Reference.Name != entry.name || !authorization.UUID(v.Reference.UID) || seen[v.Reference.UID] || !authorization.UUID(v.OperationID) || !preparationDigestValid(v.TemplateDigest) {
			return false
		}
		seen[v.Reference.UID] = true
	}
	return w.Deployment.OperationID != w.Account.OperationID && w.Deployment.OperationID != w.Lease.OperationID && w.Account.OperationID != w.Lease.OperationID
}

// BuildPublicRuntimeWorkerBinding translates original completed producer
// receipts into a closed input. This pure function provides provenance only;
// the role root independently reads the same journals and live objects before
// any credential effect. A supplied snapshot is never current authority.
func BuildPublicRuntimeWorkerBinding(resources contracts.InitialRuntimeResourceSnapshot, inventory InitialRuntimeResourceInventory, configuration contracts.ConfigurationRuntimeRoleSnapshot) (contracts.PublicRuntimeWorkerBinding, error) {
	var zero contracts.PublicRuntimeWorkerBinding
	v := resources.State
	c := configuration.State
	if (v.WorkerLayout != contracts.HubWorkerInstalledLayout && v.WorkerLayout != contracts.HubWorkerProviderInstalledLayout) || !configurationWorkerInputsStateValid(c.Input.InstallationID, v, time.Now()) || !authorization.UUID(resources.UID) || !authorization.UUID(configuration.UID) || len(v.Objects) != len(initialRuntimeResourceItems) || c.Launch == nil || c.Launch.Receipt == nil || !configurationRoleStateValid(c.Input, c, time.Now()) || inventory.Namespace != c.Input.Namespace || inventory.WorkerDeployment != c.Input.Deployment || inventory.WorkerAccount != c.Input.ServiceAccount || inventory.FleetSource != c.Input.FleetSource || inventory.OwnerSource != c.Input.OwnerSource {
		return zero, cfg.ErrChanged
	}
	object := func(index int, ref contracts.WorkerObjectReference) (contracts.PublicRuntimeWorkerObject, error) {
		e := v.Objects[index]
		if e.Item != initialRuntimeResourceItems[index] || e.Receipt == nil || e.Receipt.UID != ref.UID {
			return contracts.PublicRuntimeWorkerObject{}, cfg.ErrChanged
		}
		return contracts.PublicRuntimeWorkerObject{Reference: ref, OperationID: e.OperationID, TemplateDigest: e.TemplateDigest}, nil
	}
	d, err := object(11, inventory.WorkerDeployment)
	if err != nil {
		return zero, err
	}
	a, err := object(1, inventory.WorkerAccount)
	if err != nil {
		return zero, err
	}
	l, err := object(13, inventory.LeaderLease)
	if err != nil {
		return zero, err
	}
	w := contracts.PublicRuntimeWorkerBinding{Resources: contracts.WorkerObjectReference{Name: "asservat-runtime-resources-" + strings.ReplaceAll(c.Input.InstallationID, "-", ""), UID: resources.UID}, ResourceSetupID: v.SetupID, ResourceBinding: v.BindingDigest, WorkerLayout: v.WorkerLayout, FleetGuardName: inventory.FleetGuard.Name, Deployment: d, Account: a, Lease: l, ConfigurationRoot: contracts.WorkerObjectReference{Name: "asservat-configuration-roles-" + strings.ReplaceAll(c.Input.InstallationID, "-", ""), UID: configuration.UID}, ConfigurationSetupID: c.OperationID, Configuration: c.Input}
	if v.WorkerLayout == contracts.HubWorkerProviderInstalledLayout {
		p := v.WorkerInputs
		if v.WorkerProvider == nil || p == nil || p.Receipt == nil || p.ConfigurationRoot != w.ConfigurationRoot || p.ConfigurationSetupID != w.ConfigurationSetupID || c.Projection == nil || p.SQLProjection.UID != c.Projection.SecretUID || c.Launch.Configuration != p.Receipt.Configuration || c.Launch.Providers != p.AuditCredentials {
			return zero, cfg.ErrChanged
		}
		w.Provider = contracts.PublicRuntimeWorkerProviderBinding{Selection: *v.WorkerProvider, InputOperationID: p.OperationID, PublicDigest: p.PublicDigest, Configuration: p.Receipt.Configuration}
	} else if v.WorkerProvider != nil || v.WorkerInputs != nil {
		return zero, cfg.ErrChanged
	}
	in := contracts.PublicRuntimeRoles{InstallationID: c.Input.InstallationID, InitialClaimID: c.Input.InitialClaimID, ClusterID: c.Input.ClusterID, Namespace: c.Input.Namespace, OwnerConfigurationUID: c.Input.OwnerSource.UID, Worker: w}
	if !publicRuntimeWorkerBindingValid(in) {
		return zero, cfg.ErrChanged
	}
	return w, nil
}
