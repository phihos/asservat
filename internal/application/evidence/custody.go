package evidence

import (
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"time"
)

// CopyVerifier has independent read credentials. It verifies exact ciphertext
// identities, sizes and full hashes; semantic manifest verification is separate.
type CopyVerifier interface {
	VerifyCopies(context.Context, artifact.Registration, artifact.Copies) error
}

type Custodian struct {
	Ledger   privacy.CopyLedger
	Verifier CopyVerifier
}

func (c Custodian) VerifyAndStore(ctx context.Context, r artifact.Registration, copies artifact.Copies) error {
	if r.Validate() != nil || copies.Validate(r) != nil {
		return artifact.ErrInvalid
	}
	if c.Ledger == nil || c.Verifier == nil {
		return privacy.ErrUnavailable
	}
	// Confirm a durable obligation exists before reading. The final transaction
	// rechecks immutable scope, current fences and post-lock database time.
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
	if err = c.Verifier.VerifyCopies(ctx, r, copies); err != nil {
		return err
	}
	return c.Ledger.StoreCopies(ctx, r, copies)
}
