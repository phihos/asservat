// Package capacity defines protected storage backing, not collection authority.
package capacity

import (
	"context"
	"time"
)

// StorageAllocation is supplied by the accepted Kubernetes configuration
// reconciler, never chosen by a capture caller. Protected space is not borrowed.
type StorageAllocation struct {
	ID, PoolID, ScopeID, ServiceClass      string
	PoolRevision, Revision, Bytes, Objects int64
	ValidUntil                             time.Time
}
type StorageBacking interface {
	ProvisionAllocation(context.Context, StorageAllocation) error
}
