package kubernetes

import (
	"context"
	"sync"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
)

// InitialRuntimeBridge owns exactly two fixed policy CAS operations. Its
// concrete native source is the same independently checked configuration
// producer used for the three bootstrap roles. It never edits the retired
// initial root, creates runtime credentials, starts a Pod or accepts SQL trust.
type InitialRuntimeBridge struct {
	preparer                      *InitialPreparer
	source                        *ConfigurationRoleSource
	effects                       app.InitialRuntimeBridgeEffects
	record                        audit.InitialInstallation
	administration                cfg.InitialRuntimeBridgeAdministration
	initial                       contracts.InitialInstaller
	binding, rootUID              string
	policies                      [3]*admission.ValidatingAdmissionPolicy
	guards                        [3]*configMapProtection
	ctx                           context.Context
	cancel                        context.CancelFunc
	mu                            sync.Mutex
	closed, busy, createAttempted bool
	joined                        sync.WaitGroup
}
