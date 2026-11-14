package kubernetes

import (
	"context"
	"sync"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
)

// OwnerIdentityRoleRoot is the private pre-Ready installer compartment. Its
// current proof binds the original inert resources or spent exact launch; it
// never weakens PublicRuntimeRoleRoot's separate running-owner requirement.
type OwnerIdentityRoleRoot struct {
	bridge                           *InitialRuntimeBridge
	resources                        *InitialRuntimeResources
	accepted                         fleetapp.OwnerConfigurationReader
	input                            contracts.OwnerIdentityRoles
	resourceCreatedAt, resourceUntil time.Time
	attemptedClaims                  map[string]bool
	attemptedRoleReceipts            map[string]bool // fresh operation receipt attempts, root serialized
	operationRootUID                 string
	pendingOperationRoot             *contracts.OwnerIdentityRoleState
	ctx                              context.Context
	cancel                           context.CancelFunc
	mu                               sync.Mutex
	closed, busy, createAttempted    bool
	joined                           sync.WaitGroup
	ownerOperation                   *OwnerIdentityOperation  // fresh-only admitted phase; guarded by mu
	splitProjection                  *ProviderOwnerProjection // one controller retains all uncertain projection spend
	bracket                          *ownerBracket            // open installation bracket (ADR-316); guarded by mu
}
