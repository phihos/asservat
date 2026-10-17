package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

type DownloadWorkerAuditObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ auditapp.DownloadWorkerWriter = (*DownloadWorkerAuditObjects)(nil)

func (s *DownloadWorkerAuditObjects) WriteDownloadWorkerIntent(ctx context.Context, i authorization.DownloadWorkerIntent) (audit.Receipt, error) {
	var out audit.Receipt
	if s == nil || ctx == nil || s.Store == nil || s.Seal == nil || s.Open == nil || !i.Valid() {
		return out, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	b, e := framed.SealDownloadWorker(ctx, s.Seal, i)
	if e != nil {
		return out, e
	}
	key := audit.DownloadWorkerAuditKey(i)
	o, c, e := s.Store.putControlAudit(ctx, key, b, 128<<10)
	if e != nil {
		return out, e
	}
	if e = framed.VerifyDownloadWorker(ctx, s.Open, i, c); e != nil {
		return out, e
	}
	out = audit.Receipt{Key: key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}
	if !out.ValidDownloadWorker(i) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return out, nil
}
