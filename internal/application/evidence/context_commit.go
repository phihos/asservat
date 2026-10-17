package evidence

import (
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"time"
)

// ContextVerifier authenticates the full chain and checks the native projection.
// Expected facts must come from accepted control state, never the upload itself.
type ContextVerifier interface {
	VerifyContext(context.Context, artifact.ContextExpectation, artifact.Copies) error
}

type ContextCustodian struct {
	Ledger   privacy.CopyLedger
	Verifier ContextVerifier
}

// VerifyAndStore records unpublished copy receipts only after semantic and byte
// verification. It neither creates a catalog artifact nor supplies authorization
// or durable object audit. Current authority must wrap this internal role.
func (c ContextCustodian) VerifyAndStore(ctx context.Context, e artifact.ContextExpectation, copies artifact.Copies) error {
	if e.Validate() != nil || copies.Validate(e.Registration) != nil {
		return artifact.ErrInvalid
	}
	if c.Ledger == nil || c.Verifier == nil {
		return privacy.ErrUnavailable
	}
	r := e.Registration
	record, err := c.Ledger.Lookup(ctx, r.Location)
	if err != nil {
		return err
	}
	if !record.Registration.Equal(r) {
		return privacy.ErrConflict
	}
	if record.State != artifact.Reserved && record.State != artifact.StoredUnpublished {
		return privacy.ErrExpired
	}
	if err = c.Ledger.CheckVerification(ctx, r); err != nil {
		return err
	}
	deadline := r.WriteUntil
	if limit := time.Now().Add(30 * time.Second); limit.Before(deadline) {
		deadline = limit
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err = c.Verifier.VerifyContext(ctx, e, copies); err != nil {
		return err
	}
	return c.Ledger.StoreCopies(ctx, r, copies)
}
