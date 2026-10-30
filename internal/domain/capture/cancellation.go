package capture

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

type CancellationRequest struct {
	CaptureID        string
	ExpectedRevision int64
	IdempotencyKey   string
}

func (r CancellationRequest) Valid() bool {
	return authorization.UUID(r.CaptureID) && r.ExpectedRevision >= 1 && r.ExpectedRevision <= MaxProgressRevision && identity.Text(r.IdempotencyKey, 128)
}

type CancellationCheck struct {
	RootID                string
	Request               CancellationRequest
	Identity              identity.Identity
	Recovery              artifact.RecoveryProof
	CheckedAt, ValidUntil time.Time
}

func (c CancellationCheck) Valid(now time.Time) bool {
	return authorization.UUID(c.RootID) && c.Request.Valid() && c.Identity.Valid(now) && c.Recovery.Valid(now) && identity.Fresh(c.CheckedAt, c.ValidUntil, now, 5*time.Second) && !c.ValidUntil.After(c.Identity.ValidUntil) && !c.ValidUntil.After(c.Recovery.FreshUntil)
}

// Cancellation records intent to stop remaining capture work. It is not a
// confirmation that a remote owner has joined, nor authority over a live source.
type Cancellation struct {
	CaptureID              string
	Phase                  string
	Revision               int64
	Requested              bool
	ObservedAt, ValidUntil time.Time
}

func (c Cancellation) Valid(now time.Time) bool {
	if !authorization.UUID(c.CaptureID) || c.Revision < 1 || c.Revision > MaxProgressRevision || !identity.Fresh(c.ObservedAt, c.ValidUntil, now, 5*time.Second) {
		return false
	}
	switch c.Phase {
	case "Pending", "Validating", "AwaitingApproval", "Armed", "Queued", "Running", "Finalizing", "Succeeded", "Partial", "Failed", "Cancelled", "Indeterminate":
		return true
	}
	return false
}
