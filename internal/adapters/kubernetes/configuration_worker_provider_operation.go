package kubernetes

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// ConfigurationWorkerProviderOperation owns one initial/final native pair.
// Only this reader can create it. It does not implement a general source port,
// accept caller-built facts or renew its original interval. Credential control
// belongs between the two actual brackets, with separate current SQL recovery.
type ConfigurationWorkerProviderOperation struct {
	self     *ConfigurationWorkerProviderOperation
	reader   *ConfigurationWorkerProviderReader
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	until    time.Time
	started  time.Time
	busy     bool
	closed   bool
	finished bool
	changed  chan struct{}
	epoch    string
	manifest contracts.ConfigurationRuntimeCredentialManifest
	mounted  map[string][]byte
	initial  configurationProviderNative
	tokens   *configurationWorkerTokenInterval
}
