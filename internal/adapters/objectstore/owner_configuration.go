package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
	"time"
)

type OwnerConfigurationAuditObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ app.OwnerConfigurationWriter = (*OwnerConfigurationAuditObjects)(nil)

func (s *OwnerConfigurationAuditObjects) WriteOwnerConfiguration(ctx context.Context, c value.OwnerConfiguration) (audit.Receipt, error) {
	var out audit.Receipt
	if s == nil || ctx == nil || s.Store == nil || s.Seal == nil || s.Open == nil || !c.Valid() {
		return out, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	b, e := framed.SealOwnerConfiguration(ctx, s.Seal, c)
	if e != nil {
		return out, e
	}
	key := audit.OwnerConfigurationAuditKey(c)
	o, raw, e := s.Store.putControlAudit(ctx, key, b, 128<<10)
	if e != nil {
		return out, e
	}
	if e = framed.VerifyOwnerConfiguration(ctx, s.Open, c, raw); e != nil {
		return out, e
	}
	out = audit.Receipt{Key: key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}
	if !out.ValidOwnerConfiguration(c) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return out, nil
}
