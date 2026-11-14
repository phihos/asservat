package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/contracts"
)

// InitialBootstrapManagerClaim is a process-owned current observation. Fresh
// is true only after this call's acknowledged original private-state CAS. A
// replay returns the same intent with Fresh=false and is lookup-only in SQL.
type InitialBootstrapManagerClaim struct {
	State      contracts.InitialBootstrapState
	Fresh      bool
	ValidUntil time.Time
}
