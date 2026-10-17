package kubernetes

import "asservat.local/asservat/internal/contracts"

// These four public values select original provenance. They carry neither
// credentials nor a digest of private material and confer no current authority.
func capacityProjectionAnnotations(resourceUID, setupID string, p *contracts.CapacityRuntimeProjectionClaim) map[string]string {
	return map[string]string{"asservat.io/runtime-resource-uid": resourceUID, "asservat.io/runtime-resource-setup": setupID, "asservat.io/projection-id": p.OperationID, "asservat.io/projection-public": p.PublicDigest}
}
