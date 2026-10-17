package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
)

const contextVerificationFormat = "asservat-context-verification-audit/v1"

func SealContextVerification(ctx context.Context, keys evidence.KeySealer, r audit.ContextVerification) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, contextVerificationFormat, r.RootID, r.CaptureID, r, 64<<10)
}
func VerifyContextVerification(ctx context.Context, keys evidence.KeyOpener, r audit.ContextVerification, encoded []byte) error {
	if keys == nil || !r.Valid() || len(encoded) == 0 || len(encoded) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, contextVerificationFormat, r.RootID, r.CaptureID, r, encoded, 64<<10)
}
