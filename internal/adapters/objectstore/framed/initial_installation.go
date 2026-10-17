package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
)

const initialInstallationFormat = "asservat-initial-installation-audit/v1"

func SealInitialInstallation(ctx context.Context, keys evidence.KeySealer, r audit.InitialInstallation) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, initialInstallationFormat, r.Scope.InstallationID, r.Claim.ID, r, 8<<10)
}
func VerifyInitialInstallation(ctx context.Context, keys evidence.KeyOpener, r audit.InitialInstallation, encoded []byte) error {
	if keys == nil || !r.Valid() || len(encoded) == 0 || len(encoded) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, initialInstallationFormat, r.Scope.InstallationID, r.Claim.ID, r, encoded, 8<<10)
}
