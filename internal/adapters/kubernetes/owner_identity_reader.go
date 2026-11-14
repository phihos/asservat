package kubernetes

import (
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
)

// InstalledOwnerIdentityReader is what remains of the hub-api's former
// startup provenance check (ADR-328 removed it from the hub-api): the
// hub-worker's capacity owner check still reads the original Deployment
// through get and deployment until that path is removed.
type InstalledOwnerIdentityReader struct {
	client     *PermissionClient
	protection *OwnerWorkloadProtection
	input      contracts.OwnerDeployment
	activation contracts.OwnerIdentityActivation
	tokens     app.OwnerPodToken
	podUID     string
}
