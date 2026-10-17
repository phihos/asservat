package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
)

func SealDownloadWorker(ctx context.Context, k evidence.KeySealer, i authorization.DownloadWorkerIntent) ([]byte, error) {
	if k == nil || !i.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-download-worker-intent/v1", i.Authority.Scope.RootID, i.ID, i, 64<<10)
}
func VerifyDownloadWorker(ctx context.Context, k evidence.KeyOpener, i authorization.DownloadWorkerIntent, b []byte) error {
	if k == nil || !i.Valid() || len(b) == 0 || len(b) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-download-worker-intent/v1", i.Authority.Scope.RootID, i.ID, i, b, 64<<10)
}
