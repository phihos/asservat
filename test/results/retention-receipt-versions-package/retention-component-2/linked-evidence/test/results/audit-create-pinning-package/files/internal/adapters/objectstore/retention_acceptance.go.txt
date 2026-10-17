package objectstore

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	app "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

type RetentionAcceptanceObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ app.RetentionAcceptanceWriter = (*RetentionAcceptanceObjects)(nil)

func (o *RetentionAcceptanceObjects) WriteRetentionAcceptance(ctx context.Context, r audit.RetentionAcceptance) (audit.Receipt, error) {
	if o.Store == nil || o.Seal == nil || o.Open == nil || !r.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key := audit.RetentionAcceptanceKey(r.RootID, r.ID)
	encoded, err := framed.SealRetentionAcceptance(ctx, o.Seal, r)
	if err != nil {
		return audit.Receipt{}, err
	}
	object, body, err := o.Store.putControlAudit(ctx, key, encoded, 512<<10)
	if err != nil {
		return audit.Receipt{}, err
	}
	if err = framed.VerifyRetentionAcceptance(ctx, o.Open, r, body); err != nil {
		return audit.Receipt{}, err
	}
	receipt := audit.Receipt{Key: key, Version: object.VersionID, ETag: object.ETag, Bytes: object.Bytes, SHA256: object.SHA256}
	if !receipt.ValidRetentionAcceptance(r.RootID, r.ID) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return receipt, nil
}
