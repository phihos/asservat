package objectstore

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

// PolicyAcceptanceObjects needs audit-only store/KMS credentials and qualified
// immutable-write policy. It has no artifact acquisition or unwrap interface.
type PolicyAcceptanceObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ auditapp.PolicyAcceptanceWriter = (*PolicyAcceptanceObjects)(nil)

func (a *PolicyAcceptanceObjects) WritePolicyAcceptance(ctx context.Context, r audit.PolicyAcceptance) (audit.Receipt, error) {
	var out audit.Receipt
	if a.Store == nil || a.Seal == nil || a.Open == nil || !r.Valid() {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key := audit.PolicyAcceptanceKey(r.RootID, r.ID)
	cipher, err := framed.SealPolicyAcceptance(ctx, a.Seal, r)
	if err != nil {
		return out, err
	}
	object, body, err := a.Store.putControlAudit(ctx, key, cipher, 128<<10)
	if err != nil {
		return out, err
	}
	if err = framed.VerifyPolicyAcceptance(ctx, a.Open, r, body); err != nil {
		return out, err
	}
	out = audit.Receipt{Key: key, Version: object.VersionID, ETag: object.ETag, Bytes: object.Bytes, SHA256: object.SHA256}
	if !out.ValidPolicyAcceptance(r.RootID, r.ID) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return out, nil
}
