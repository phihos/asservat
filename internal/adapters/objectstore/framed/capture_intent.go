package framed

import (
	"context"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

const captureIntentFormat = "asservat-capture-intent-audit/v1"

func SealCaptureIntent(ctx context.Context, keys evidence.KeySealer, r audit.CaptureIntent) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, captureIntentFormat, r.RootID, r.CaptureID, r, 64<<10)
}
func VerifyCaptureIntent(ctx context.Context, keys evidence.KeyOpener, r audit.CaptureIntent, encoded []byte) error {
	if keys == nil || !r.Valid() || len(encoded) == 0 || len(encoded) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, captureIntentFormat, r.RootID, r.CaptureID, r, encoded, 64<<10)
}
