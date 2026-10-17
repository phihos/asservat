package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
)

func SealDownloadWindowIntent(ctx context.Context, k evidence.KeySealer, r audit.DownloadWindowIntent) ([]byte, error) {
	if k == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-download-window-intent/v1", r.Window.Authority.Scope.RootID, r.Window.ID, r, 64<<10)
}
func VerifyDownloadWindowIntent(ctx context.Context, k evidence.KeyOpener, r audit.DownloadWindowIntent, b []byte) error {
	if k == nil || !r.Valid() || len(b) == 0 || len(b) > int(artifact.DownloadWindowAuditBytes) {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-download-window-intent/v1", r.Window.Authority.Scope.RootID, r.Window.ID, r, b, 64<<10)
}
func SealDownloadWindowOutcome(ctx context.Context, k evidence.KeySealer, r audit.DownloadWindowAuditOutcome) ([]byte, error) {
	if k == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-download-window-outcome/v1", r.Intent.Window.Authority.Scope.RootID, r.Intent.Window.ID, r, 64<<10)
}
func VerifyDownloadWindowOutcome(ctx context.Context, k evidence.KeyOpener, r audit.DownloadWindowAuditOutcome, b []byte) error {
	if k == nil || !r.Valid() || len(b) == 0 || len(b) > int(artifact.DownloadWindowAuditBytes) {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-download-window-outcome/v1", r.Intent.Window.Authority.Scope.RootID, r.Intent.Window.ID, r, b, 64<<10)
}
