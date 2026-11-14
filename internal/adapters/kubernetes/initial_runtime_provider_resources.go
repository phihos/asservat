package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
)

func initialRuntimeObservationSelectionValid(worker, owner, format string) bool {
	return format == "" || format == contracts.OwnerObservationOperationFormat && worker == contracts.HubWorkerProviderInstalledLayout && owner == contracts.OwnerProviderInstalledLayout
}
