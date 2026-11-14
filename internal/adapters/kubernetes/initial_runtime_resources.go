package kubernetes

import (
	"context"
	"sync"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
)

// InitialRuntimeResources owns one fixed sequence of inert public objects.
// No arbitrary body, kind, name, API endpoint or grant is accepted by Advance.
// This component cannot create credentials, change guards, launch a process or
// establish accepted configuration. The separate bridge follows its completion.
type InitialRuntimeResources struct {
	ownerProjectionRoot *OwnerIdentityRoleRoot // first split projection lineage; guarded by mu

	preparer                    *InitialPreparer
	effects                     app.InitialRuntimeBridgeEffects
	record                      audit.InitialInstallation
	initial                     contracts.InitialInstaller
	ownerRoots                  [][]byte
	names                       initialRuntimeResourceNames
	binding, rootUID            string
	workerLayout, ownerLayout   string
	observationFormat           string
	ownerFleet                  bool
	workerProvider              *contracts.ConfigurationProviderSelection
	ownerProvider               *contracts.OwnerProviderSelection
	ctx                         context.Context
	cancel                      context.CancelFunc
	mu                          sync.Mutex
	closed, busy, freshRootUsed bool
	joined                      sync.WaitGroup
}
