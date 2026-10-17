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

type LifecycleObjects struct {
	Store    *Store
	Seal     evidence.KeySealer
	Open     evidence.KeyOpener
	Signer   app.LifecycleSigner
	Verifier app.LifecycleVerifier
}

var _ app.LifecycleWriter = (*LifecycleObjects)(nil)

func (a *LifecycleObjects) WriteLifecycleDecision(ctx context.Context, r value.LifecycleDecision) (audit.Receipt, error) {
	var out audit.Receipt
	if a == nil || a.Store == nil || a.Seal == nil || a.Open == nil || a.Signer == nil || a.Verifier == nil || !r.Valid() {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cipher, err := framed.SealLifecycle(ctx, a.Seal, a.Signer, r)
	if err != nil {
		return out, err
	}
	key := audit.LifecycleKey(r.RootID, r.ID)
	o, body, err := a.Store.putControlAudit(ctx, key, cipher, 128<<10)
	if err != nil {
		return out, err
	}
	if err = framed.VerifyLifecycle(ctx, a.Open, a.Verifier, r, body); err != nil {
		return out, err
	}
	out = audit.Receipt{Key: key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}
	if !out.ValidLifecycle(r.RootID, r.ID) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return out, nil
}
