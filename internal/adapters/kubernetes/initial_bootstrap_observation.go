package kubernetes

import (
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// InitialBootstrapObserver owns only original public observations and a
// bounded observation-only credential. No method creates identities, reads a
// private seed, touches SQL/providers or refreshes a target one-use token.
type InitialBootstrapObserver struct {
	bootstrap      *InitialBootstrap
	projection     contracts.InitialBootstrapObservation
	configuration  contracts.InitialPreparer
	mu             sync.Mutex
	closed, active bool
	joined         sync.WaitGroup
	token          string
	expires        time.Time
	issues         int
	now            func() time.Time
}
