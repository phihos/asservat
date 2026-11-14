package kubernetes

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// A separate read-only purpose. Implementations cannot obtain an effect method
// or an execution handle from this type. Entry exposes no credential journal.
type OwnerProjectionFinalizationVerification interface {
	FinalizeOwnerProjectionOperation(context.Context, *OwnerProjectionFinalization) (OwnerProjectionAdvance, error)
}

type OwnerProjectionFinalization struct {
	self           *OwnerProjectionFinalization
	controller     *ProviderOwnerProjection
	pending        *ownerProjectionPending
	prefix         *ownerProjectionPreflight
	provider       ownerIdentityProviderObservation
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	work           sync.WaitGroup
	closed         bool
	until          time.Time
	phase          atomic.Uint32
	versionMatched atomic.Bool
	first, current ownerIdentityOperationNative
	input          contracts.OwnerDeployment
	activation     contracts.OwnerIdentityActivation
	data           map[string][]byte
	// failure keeps the first callback failure's closed codes; the SQL facet
	// returns only its own normalized error.
	failure ownerProjectionDiagnosticSlot
}
