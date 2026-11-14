package kubernetes

import (
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

func configurationWorkerProviderBound(in contracts.PublicRuntimeRoles) bool {
	w, p := in.Worker, in.Worker.Provider
	if w.WorkerLayout == contracts.HubWorkerInstalledLayout {
		return p == (contracts.PublicRuntimeWorkerProviderBinding{})
	}
	if w.WorkerLayout != contracts.HubWorkerProviderInstalledLayout ||
		providerconfig.ValidateConfigurationProviderSelection(in.InstallationID, p.Selection) != nil ||
		!authorization.UUID(p.InputOperationID) || !preparationDigestValid(p.PublicDigest) ||
		p.Configuration.Name != runtimeResourceNames(in.InstallationID).WorkerInputs || !authorization.UUID(p.Configuration.UID) {
		return false
	}
	for _, id := range []string{w.ResourceSetupID, w.ConfigurationSetupID, w.Account.OperationID, w.Deployment.OperationID, w.Lease.OperationID} {
		if id == p.InputOperationID {
			return false
		}
	}
	for _, uid := range []string{w.Resources.UID, w.ConfigurationRoot.UID, w.Account.Reference.UID, w.Deployment.Reference.UID, w.Lease.Reference.UID, p.Selection.AuditCredentials.UID} {
		if uid == p.Configuration.UID {
			return false
		}
	}
	return true
}
