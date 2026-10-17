package capacity

import (
	"context"
	"time"
)

// ContextControlPool and ContextControlAllocation are protected C07
// configuration inputs, never capture caller parameters. Slots bound logical
// context record sets, not physical PostgreSQL/WAL/backup bytes. Each first
// acceptance reserves both a full-record and a future replay-record slot.
// Revision updates preserve identity/spend and can adjust only unspent backing.
// This slice neither retires records nor releases either charge.
type ContextControlPool struct {
	ExpectedRevision           int64
	Paused                     bool
	ObservedAt, FreshUntil     time.Time
	RootID                     string
	Revision                   int64
	FullRecords, ReplayRecords int64
	ValidUntil                 time.Time
}

type ContextControlAllocation struct {
	ExpectedRevision           int64
	Paused                     bool
	ObservedAt, FreshUntil     time.Time
	RootID, AllocationID       string
	PoolRevision, Revision     int64
	FullRecords, ReplayRecords int64
	ValidUntil                 time.Time
}

type ContextControlBacking interface {
	ProvisionContextControlPool(context.Context, ContextControlPool) error
	ProvisionContextControlAllocation(context.Context, ContextControlAllocation) error
}
