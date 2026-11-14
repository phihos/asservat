package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
)

// InstalledWorkerProjectionReader reads only the original public resource journal and
// the dedicated projection's metadata. The latter named GET also permits the
// already-mounted dedicated payload under native RBAC; Accept is not an ACL.
// It never opens the private role root or accepts file existence as activation.
type InstalledWorkerProjectionReader struct {
	client *PermissionClient
	guard  *OwnerWorkloadProtection
	input  contracts.HubWorkerDeployment
}
