package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

type WorkerConfigurationAuditObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ app.WorkerConfigurationWriter = (*WorkerConfigurationAuditObjects)(nil)

func (s *WorkerConfigurationAuditObjects) WriteWorkerConfiguration(ctx context.Context, c value.DownloadWorkerConfiguration) (audit.Receipt, error) {
	var out audit.Receipt
	if s == nil || ctx == nil || s.Store == nil || s.Seal == nil || s.Open == nil || !c.Valid() {
		return out, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	b, e := framed.SealWorkerConfiguration(ctx, s.Seal, c)
	if e != nil {
		return out, e
	}
	key := audit.WorkerConfigurationAuditKey(c)
	o, raw, e := s.Store.putControlAudit(ctx, key, b, 64<<10)
	if e != nil {
		return out, e
	}
	if e = framed.VerifyWorkerConfiguration(ctx, s.Open, c, raw); e != nil {
		return out, e
	}
	out = audit.Receipt{Key: key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}
	if !out.ValidWorkerConfiguration(c) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return out, nil
}
