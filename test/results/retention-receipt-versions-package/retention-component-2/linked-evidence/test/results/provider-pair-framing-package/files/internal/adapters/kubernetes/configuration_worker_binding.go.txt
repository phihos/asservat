package kubernetes

import (
	"encoding/json"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
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

func configurationWorkerProviderMatches(installation string, v contracts.InitialRuntimeResourceState, w contracts.PublicRuntimeWorkerBinding) bool {
	if w.WorkerLayout == contracts.HubWorkerInstalledLayout {
		return v.WorkerProvider == nil && v.WorkerInputs == nil && w.Provider == (contracts.PublicRuntimeWorkerProviderBinding{})
	}
	p := v.WorkerInputs
	return w.WorkerLayout == contracts.HubWorkerProviderInstalledLayout && v.WorkerLayout == w.WorkerLayout &&
		v.OwnerLayout == contracts.OwnerProviderInstalledLayout && v.WorkerProvider != nil && *v.WorkerProvider == w.Provider.Selection &&
		p != nil && p.Receipt != nil && p.OperationID == w.Provider.InputOperationID && p.PublicDigest == w.Provider.PublicDigest &&
		p.Receipt.Configuration == w.Provider.Configuration && p.ConfigurationRoot == w.ConfigurationRoot && p.ConfigurationSetupID == w.ConfigurationSetupID
}

// The versioned public digest covers the complete generated document. It has
// no secret bytes and cannot substitute for current source/provider proofs.
// Both original CREATE and every later independent read use this definition.
func configurationWorkerInputDigest(in contracts.HubWorkerDeployment) (string, error) {
	b, err := json.Marshal(in)
	if err != nil || len(b) > contracts.OwnerDeploymentMaxBytes {
		return "", cfg.ErrInvalid
	}
	return preparationDigest(struct {
		Format string                        `json:"format"`
		Input  contracts.HubWorkerDeployment `json:"input"`
	}{"asservat-configuration-worker-input/v1", in}), nil
}
