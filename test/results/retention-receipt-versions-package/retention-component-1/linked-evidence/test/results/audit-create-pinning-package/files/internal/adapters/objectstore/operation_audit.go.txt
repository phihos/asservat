package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"time"
)

// Create and Find are deliberately separate. Only the acknowledged first SQL
// claim reaches Create; lost replies use Find with no reseal or another PUT.
type OperationAuditObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ app.OperationObjects = (*OperationAuditObjects)(nil)

func (a *OperationAuditObjects) CreateOperationIntent(ctx context.Context, r audit.OperationIntent) (audit.Receipt, error) {
	return a.intent(ctx, r, true)
}
func (a *OperationAuditObjects) FindOperationIntent(ctx context.Context, r audit.OperationIntent) (audit.Receipt, error) {
	return a.intent(ctx, r, false)
}
func (a *OperationAuditObjects) CreateOperationOutcome(ctx context.Context, r audit.OperationOutcome) (audit.Receipt, error) {
	return a.outcome(ctx, r, true)
}
func (a *OperationAuditObjects) FindOperationOutcome(ctx context.Context, r audit.OperationOutcome) (audit.Receipt, error) {
	return a.outcome(ctx, r, false)
}
func (a *OperationAuditObjects) intent(ctx context.Context, r audit.OperationIntent, create bool) (audit.Receipt, error) {
	if !r.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	return a.write(ctx, r, "intent", create, func(c context.Context) ([]byte, error) { return framed.SealOperationIntent(c, a.Seal, r) }, func(c context.Context, b []byte) error { return framed.VerifyOperationIntent(c, a.Open, r, b) })
}
func (a *OperationAuditObjects) outcome(ctx context.Context, r audit.OperationOutcome, create bool) (audit.Receipt, error) {
	if !r.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	return a.write(ctx, r.Intent, "outcome", create, func(c context.Context) ([]byte, error) { return framed.SealOperationOutcome(c, a.Seal, r) }, func(c context.Context, b []byte) error { return framed.VerifyOperationOutcome(c, a.Open, r, b) })
}
func (a *OperationAuditObjects) write(ctx context.Context, in audit.OperationIntent, phase string, create bool, seal func(context.Context) ([]byte, error), verify func(context.Context, []byte) error) (audit.Receipt, error) {
	if a == nil || a.Store == nil || a.Seal == nil || a.Open == nil || ctx == nil || ctx.Err() != nil || !time.Now().Before(in.WriteUntil) {
		return audit.Receipt{}, app.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, in.WriteUntil)
	defer cancel()
	key := audit.OperationAuditKey(in.RootID, in.ID, phase)
	var o Object
	var b []byte
	var err error
	if create {
		ciphertext, sealErr := seal(ctx)
		if sealErr != nil || len(ciphertext) > audit.OperationCipherLimit {
			return audit.Receipt{}, app.ErrUnavailable
		}
		defer clear(ciphertext)
		o, b, err = a.Store.putControlAudit(ctx, key, ciphertext, audit.OperationCipherLimit)
	} else {
		o, b, err = a.Store.readControlAudit(ctx, key, audit.OperationCipherLimit)
	}
	if err != nil {
		return audit.Receipt{}, app.ErrUnavailable
	}
	defer clear(b)
	if err = verify(ctx, b); err != nil || ctx.Err() != nil {
		return audit.Receipt{}, app.ErrUnavailable
	}
	receipt := audit.Receipt{Key: key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}
	if !receipt.ValidOperation(in.RootID, in.ID, phase) {
		return audit.Receipt{}, app.ErrUnavailable
	}
	return receipt, nil
}
