package kubernetes

import (
	"context"
	"sync"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// The existing SQL producer implements both fixed read-only verifications.
// The second cannot issue roles or import a replacement credential after launch.
type ConfigurationWorkerRoleVerification interface {
	VerifyConfigurationRuntimeRoles(context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error)
	VerifyLaunchedConfigurationRuntimeRoles(context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error)
}

// ConfigurationWorkerInputs publishes one public ConfigMap under the original
// retained bridge and exposes the separate original launch/acknowledgement phases.
// It cannot qualify S3 backend capability or repair an uncertain launch.
// The externally owned roots/readers are borrowed through the complete call.
type ConfigurationWorkerInputs struct {
	bridge                  *InitialRuntimeBridge
	resources               *InitialRuntimeResources
	roles                   *ConfigurationRuntimeRoleRoot
	verification            ConfigurationWorkerRoleVerification
	setup                   *providerconfig.SetupReader
	original                contracts.InitialRuntimeResourceSnapshot
	ctx                     context.Context
	cancel                  context.CancelFunc
	mu                      sync.Mutex
	closed, busy, attempted bool
	launchAttempted         bool
	joined                  sync.WaitGroup
}
