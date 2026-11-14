package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
)

func configurationWorkerInputAnnotations(resourceUID, setupID string, p *contracts.ConfigurationWorkerInputClaim) map[string]string {
	return capacityProjectionAnnotations(resourceUID, setupID, &contracts.CapacityRuntimeProjectionClaim{OperationID: p.OperationID, PublicDigest: p.PublicDigest})
}
