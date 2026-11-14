package kubernetes

import (
	"sync"
	"sync/atomic"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// The provider endpoint and CA exist before the original preparer binds them.
// Responses model exact setup recipes over actual TLS; they are explicitly
// synthetic provider state, not a real OpenBao or scoped-IAM qualification.
type ownerOperationProviderFixture struct {
	mu        sync.Mutex
	responses map[string]any
	endpoint  contracts.ConfigurationKeyService
	reader    *providerconfig.SetupReader
	requests  atomic.Int32
	deny      atomic.Bool
}
