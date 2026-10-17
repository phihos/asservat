package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"time"
)

type DownloadAuditObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ auditapp.DownloadWriter = (*DownloadAuditObjects)(nil)

func (a *DownloadAuditObjects) WriteDownloadIntent(ctx context.Context, r audit.DownloadIntent) (audit.Receipt, error) {
	if !r.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	return a.writeDownload(ctx, r.Batch.Authority.Scope.RootID, r.SessionID, r.Batch.ID, "intent", func(ctx context.Context) ([]byte, error) { return framed.SealDownloadIntent(ctx, a.Seal, r) }, func(ctx context.Context, b []byte) error { return framed.VerifyDownloadIntent(ctx, a.Open, r, b) })
}
func (a *DownloadAuditObjects) WriteDownloadOutcome(ctx context.Context, r audit.DownloadOutcome) (audit.Receipt, error) {
	if !r.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	return a.writeDownload(ctx, r.Intent.Batch.Authority.Scope.RootID, r.Intent.SessionID, r.Intent.Batch.ID, "outcome", func(ctx context.Context) ([]byte, error) { return framed.SealDownloadOutcome(ctx, a.Seal, r) }, func(ctx context.Context, b []byte) error { return framed.VerifyDownloadOutcome(ctx, a.Open, r, b) })
}
func (a *DownloadAuditObjects) writeDownload(ctx context.Context, root, session, batch, phase string, seal func(context.Context) ([]byte, error), verify func(context.Context, []byte) error) (audit.Receipt, error) {
	var out audit.Receipt
	if a.Store == nil || a.Seal == nil || a.Open == nil {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key := audit.DownloadAuditKey(root, session, batch, phase)
	cipher, err := seal(ctx)
	if err != nil {
		return out, err
	}
	o, body, err := a.Store.putControlAudit(ctx, key, cipher, 128<<10)
	if err != nil {
		return out, err
	}
	if err = verify(ctx, body); err != nil {
		return out, err
	}
	out = audit.Receipt{Key: key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}
	if !out.ValidDownload(root, session, batch, phase) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return out, nil
}
