package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"time"
)

type ContextDeletionObjects struct {
	Store    *Store
	Seal     evidence.KeySealer
	Open     evidence.KeyOpener
	Signer   app.ContextDeletionSigner
	Verifier app.ContextDeletionVerifier
}

var _ app.ContextDeletionWriter = (*ContextDeletionObjects)(nil)

func (a *ContextDeletionObjects) WriteContextDeletion(ctx context.Context, r value.ContextDeletionCheckpoint) (audit.Receipt, error) {
	var out audit.Receipt
	if a == nil || a.Store == nil || a.Seal == nil || a.Open == nil || a.Signer == nil || a.Verifier == nil || !r.Valid() {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cipher, err := framed.SealContextDeletion(ctx, a.Seal, a.Signer, r)
	if err != nil {
		return out, err
	}
	key := audit.ContextDeletionKey(r.RootID, r.Location.AttemptID)
	o, body, err := a.Store.putControlAudit(ctx, key, cipher, 128<<10)
	if err != nil {
		return out, err
	}
	if err = framed.VerifyContextDeletion(ctx, a.Open, a.Verifier, r, body); err != nil {
		return out, err
	}
	out = audit.Receipt{Key: key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}
	if !out.ValidContextDeletion(r.RootID, r.Location.AttemptID) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return out, nil
}
