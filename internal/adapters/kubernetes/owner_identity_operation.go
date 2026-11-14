package kubernetes

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/contracts"
)

type ownerIdentityOperationPhase uint8

// OwnerIdentityOperation is a concrete admitted installer operation, not a
// serializable proof or general source interface. Only the original native
// root mints it inside its joined operation. The fresh SQL producer pins that
// exact root; a zero value or a copied caller snapshot cannot be admitted.
type OwnerIdentityOperation struct {
	mu               sync.Mutex
	work             sync.WaitGroup
	root             *OwnerIdentityRoleRoot
	ctx              context.Context
	cancel           context.CancelFunc
	phase            ownerIdentityOperationPhase
	active           bool
	initial          ownerIdentityOperationNative
	current          ownerIdentityOperationNative
	expected         contracts.OwnerIdentityRoleSnapshot
	purpose          string
	fresh            bool
	inspection       bool
	createDispatched bool
	original         time.Time
	until            time.Time
	// failure keeps the first native callback failure's closed codes; the SQL
	// facet returns only its own normalized step.
	failure atomic.Pointer[ownerOperationDiagnostic]
}
