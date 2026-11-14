package kubernetes

import (
	"context"
	"sync"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
)

// PublicRuntimeRoleRoot is a separate post-activation installer compartment.
// Only an actual administrator and the original native namespace guard can
// read/change it. It does not reuse or revive the retired initial manager.
// No SQL privilege or recovery authority is derived from this Secret.
type PublicRuntimeRoleRoot struct {
	client         *PermissionClient
	protection     *OwnerWorkloadProtection
	configurations fleetapp.OwnerConfigurationReader
	input          contracts.PublicRuntimeRoles
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	closed, busy   bool
	joined         sync.WaitGroup
}
