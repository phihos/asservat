package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
)

func SealDownloadIntent(ctx context.Context, keys evidence.KeySealer, r audit.DownloadIntent) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, "asservat-download-intent/v1", r.Batch.Authority.Scope.RootID, r.Batch.ID, r, 64<<10)
}
func VerifyDownloadIntent(ctx context.Context, keys evidence.KeyOpener, r audit.DownloadIntent, encoded []byte) error {
	if keys == nil || !r.Valid() || len(encoded) == 0 || len(encoded) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, "asservat-download-intent/v1", r.Batch.Authority.Scope.RootID, r.Batch.ID, r, encoded, 64<<10)
}
func SealDownloadOutcome(ctx context.Context, keys evidence.KeySealer, r audit.DownloadOutcome) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, "asservat-download-outcome/v1", r.Intent.Batch.Authority.Scope.RootID, r.Intent.Batch.ID, r, 64<<10)
}
func VerifyDownloadOutcome(ctx context.Context, keys evidence.KeyOpener, r audit.DownloadOutcome, encoded []byte) error {
	if keys == nil || !r.Valid() || len(encoded) == 0 || len(encoded) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, "asservat-download-outcome/v1", r.Intent.Batch.Authority.Scope.RootID, r.Intent.Batch.ID, r, encoded, 64<<10)
}
