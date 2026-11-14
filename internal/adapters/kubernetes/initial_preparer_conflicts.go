package kubernetes

import (
	"time"
)

// A retained negative result belongs to one actual local UPDATE invocation.
// Public GET observations cannot create it. There are exactly two purposes.
type initialHandoverConflict struct {
	Purpose, ID, UID, ResourceVersion string
	StartedAt, Until, CompletedAt     time.Time
}
