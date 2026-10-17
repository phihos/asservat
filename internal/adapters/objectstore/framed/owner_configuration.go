package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
)

func SealOwnerConfiguration(ctx context.Context, k evidence.KeySealer, c value.OwnerConfiguration) ([]byte, error) {
	if k == nil || !c.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-hub-owner-configuration-audit/v1", c.Pool.InstallationID, audit.OwnerConfigurationAuditKey(c), c, 64<<10)
}
func VerifyOwnerConfiguration(ctx context.Context, k evidence.KeyOpener, c value.OwnerConfiguration, b []byte) error {
	if k == nil || !c.Valid() || len(b) == 0 || len(b) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-hub-owner-configuration-audit/v1", c.Pool.InstallationID, audit.OwnerConfigurationAuditKey(c), c, b, 64<<10)
}
