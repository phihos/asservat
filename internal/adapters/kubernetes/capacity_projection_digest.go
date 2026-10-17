package kubernetes

import "asservat.local/asservat/internal/contracts"

// CapacityRuntimePublicDigest binds only public installation inputs and original
// role/setup provenance. Passwords, account keys and Secret payload hashes never
// enter the public resource journal. SQL startup still authenticates each login.
func CapacityRuntimePublicDigest(c contracts.CapacityDeployment, m contracts.CapacityCredentialManifest) string {
	return preparationDigest(struct {
		Format     string                               `json:"format"`
		Deployment contracts.CapacityDeployment         `json:"deployment"`
		Manifest   contracts.CapacityCredentialManifest `json:"manifest"`
	}{"asservat-capacity-projection-public/v1", c, m})
}
