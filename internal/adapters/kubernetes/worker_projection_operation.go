package kubernetes

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
)

type workerProjectionPurpose uint8

type workerProjectionNative struct {
	state contracts.InitialRuntimeResourceState
	owner apps.Deployment
}

// WorkerProjectionOperation is a fixed capacity or cleanup native bracket,
// minted only by the exact installed reader. An actual effect belongs between
// Begin and Finish; the handle never substitutes for its current SQL checks.
// No provider source proof, Pod identity or token refresh is inferred here.
type WorkerProjectionOperation struct {
	self                   *WorkerProjectionOperation
	reader                 *InstalledWorkerProjectionReader
	purpose                workerProjectionPurpose
	ctx                    context.Context
	cancel                 context.CancelFunc
	tokens                 *configurationWorkerTokenInterval
	initial                workerProjectionNative
	mu                     sync.Mutex
	changed                chan struct{}
	until                  time.Time
	started                time.Time
	busy, finished, closed bool
}
