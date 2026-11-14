package kubernetes

import (
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

func initialRuntimeObservationSelectionValid(worker, owner, format string) bool {
	return format == "" || format == contracts.OwnerObservationOperationFormat && worker == contracts.HubWorkerProviderInstalledLayout && owner == contracts.OwnerProviderInstalledLayout
}

func initialRuntimeProviderSelectionValid(installation, workerLayout, ownerLayout string, worker *contracts.ConfigurationProviderSelection, owner *contracts.OwnerProviderSelection) bool {
	if !contracts.InitialRuntimeLayoutsSupported(workerLayout, ownerLayout) {
		return false
	}
	if workerLayout != contracts.HubWorkerProviderInstalledLayout {
		return worker == nil && owner == nil
	}
	return worker != nil && owner != nil && providerconfig.ValidateConfigurationProviderSelection(installation, *worker) == nil && providerconfig.ValidateOwnerProviderSelection(installation, *owner) == nil && worker.AuditCredentials != owner.AuditCredentials && worker.AuditCredentials.UID != owner.AuditCredentials.UID
}

func initialProviderSecretIdentity(obj core.Secret, namespace string, ref contracts.WorkerObjectReference, key string) bool {
	if obj.APIVersion != "v1" || obj.Kind != "Secret" || obj.Name != ref.Name || obj.Namespace != namespace || string(obj.UID) != ref.UID || !identity.Text(obj.ResourceVersion, 128) || obj.DeletionTimestamp != nil || len(obj.OwnerReferences) != 0 || len(obj.Finalizers) != 0 || obj.Immutable != nil && *obj.Immutable || obj.Type != core.SecretTypeOpaque || len(obj.StringData) != 0 || len(obj.Data) > 1 {
		return false
	}
	if len(obj.Data) == 1 {
		b, ok := obj.Data[key]
		return ok && len(b) <= 32<<10
	}
	return true
}
