package providerconfig

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// ErrSetupUnavailable deliberately excludes provider bodies, tokens and URLs.
var ErrSetupUnavailable = errors.New("provider setup unavailable or does not match the selected profile")

// SetupReader is an installation-only, read-only provider client. The credential
// needs only the exact named reads in the generated inspection policy. It is
// never a runtime key credential and is never included in a setup observation.
// The public methods select fixed recipes; there is no generic request method.
type SetupReader struct {
	mu                sync.Mutex
	endpoint          contracts.OwnerProviderEndpoint
	bundledKubernetes *contracts.OwnerProviderEndpoint
	token             []byte
	http              *http.Client
	closed            bool
	active            *setupObservation
}

type setupObservation struct {
	reader            *SetupReader
	ctx               context.Context
	cancel            context.CancelFunc
	observedAt, until time.Time
	paths             map[string]bool
	done              chan struct{}
	finished          sync.Once
}
