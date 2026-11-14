package postgres

import (
	"asservat.local/asservat/internal/adapters/kubernetes"
)

// OwnerIdentityOperationSQL is the fresh installer adapter's fixed native/SQL
// boundary. This deliberate C21 -> C21 edge accepts only the concrete native
// root and its operation-owned handle; it is not another source authority port.
// The unchanged legacy producer remains available to its original callers.
type OwnerIdentityOperationSQL struct {
	roles *OwnerIdentitySQLRoles
	root  *kubernetes.OwnerIdentityRoleRoot
}
