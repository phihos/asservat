package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
)

func SealDownloadStop(ctx context.Context, keys evidence.KeySealer, d artifact.DownloadStopDecision) ([]byte, error) {
	if keys == nil || !d.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, "asservat-download-stop/v1", d.RootID, d.DownloadID, d, 8<<10)
}
func VerifyDownloadStop(ctx context.Context, keys evidence.KeyOpener, d artifact.DownloadStopDecision, b []byte) error {
	if keys == nil || !d.Valid() || len(b) == 0 || int64(len(b)) > artifact.DownloadStopCipherLimit {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, "asservat-download-stop/v1", d.RootID, d.DownloadID, d, b, 8<<10)
}
