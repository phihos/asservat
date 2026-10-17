package objectstore

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

// ClusterBootstrapAuditObjects writes the encrypted generation-1 audit record
// create-only and verifies the stored bytes before returning a receipt.
type ClusterBootstrapAuditObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

func (s *ClusterBootstrapAuditObjects) WriteClusterBootstrap(ctx context.Context, r audit.ClusterBootstrap) (audit.Receipt, error) {
	var out audit.Receipt
	if s == nil || ctx == nil || s.Store == nil || s.Seal == nil || s.Open == nil || !r.Valid() {
		return out, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	b, e := framed.SealClusterBootstrap(ctx, s.Seal, r)
	if e != nil {
		return out, e
	}
	key := audit.ClusterBootstrapAuditKey(r)
	o, raw, e := s.Store.putControlAudit(ctx, key, b, 64<<10)
	if e != nil {
		return out, e
	}
	if e = framed.VerifyClusterBootstrap(ctx, s.Open, r, raw); e != nil {
		return out, e
	}
	out = audit.Receipt{Key: key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}
	if !out.ValidClusterBootstrap(r) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return out, nil
}
