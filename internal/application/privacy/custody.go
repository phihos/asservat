// Package privacy owns copy lifecycle orchestration. No method grants access.
package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"errors"
	"time"
)

var (
	ErrUnavailable = errors.New("custody unavailable; retain the original attempt and charge")
	ErrConflict    = errors.New("immutable custody request conflicts")
	ErrCapacity    = errors.New("protected allocation unavailable")
	ErrExpired     = errors.New("custody deadline or configuration expired")
	ErrFence       = errors.New("stale custody work")
	ErrNotDue      = errors.New("deletion not due")
)

type Record struct {
	Registration artifact.Registration
	Effective    value.Deadlines
	State        string
	Copies       artifact.Copies
}
type Deletion struct {
	Registration artifact.Registration
	Effective    value.Deadlines
	Fence        int64
	LeaseUntil   time.Time
}

// CopyLedger is the storage facet of future admission/publication transactions.
// Register reserves storage; callers still need current execution/audit authority.
// StoreCopies records independent ciphertext checks, not manifest/audience approval.
type CopyLedger interface {
	Register(context.Context, artifact.Registration) (Record, error)
	Lookup(context.Context, artifact.Location) (Record, error)
	CheckVerification(context.Context, artifact.Registration) error
	StoreCopies(context.Context, artifact.Registration, artifact.Copies) error
	ClaimDeletion(context.Context, artifact.Location) (Deletion, error)
	FinishDeletion(context.Context, Deletion) error
}

// WriterBarrier must fence credentials/permits and confirm all in-flight writes
// stopped, including multipart completion, before returning. A timer or empty
// inventory is insufficient. No production implementation exists yet.
type WriterBarrier interface {
	CloseAndWait(context.Context, artifact.Registration) error
}
type AttemptPurger interface {
	PurgeAttempt(context.Context, artifact.Registration) error
}

type Cleaner struct {
	Ledger  CopyLedger
	Barrier WriterBarrier
	Purger  AttemptPurger
}

// Clean retries the same finite obligation. Any uncertain barrier, I/O or SQL
// completion leaves the reservation charged. Remote calls never hold SQL locks.
func (c Cleaner) Clean(ctx context.Context, location artifact.Location) error {
	if c.Ledger == nil || c.Barrier == nil || c.Purger == nil {
		return ErrUnavailable
	}
	d, err := c.Ledger.ClaimDeletion(ctx, location)
	if err != nil {
		return err
	}
	// Bound the complete remote pass, not merely each individual S3 request.
	// SQL still rechecks its own clock/fence before acknowledging completion.
	deadline := d.LeaseUntil
	if limit := time.Now().Add(30 * time.Second); limit.Before(deadline) {
		deadline = limit
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err = c.Barrier.CloseAndWait(ctx, d.Registration); err != nil {
		return err
	}
	if err = c.Purger.PurgeAttempt(ctx, d.Registration); err != nil {
		return err
	}
	return c.Ledger.FinishDeletion(ctx, d)
}
