package framed

import (
	"context"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

const retentionAcceptanceFormat = "asservat-retention-acceptance/v1"

func SealRetentionAcceptance(ctx context.Context, keys evidence.KeySealer, r audit.RetentionAcceptance) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, retentionAcceptanceFormat, r.RootID, r.ID, r, 256<<10)
}
func VerifyRetentionAcceptance(ctx context.Context, keys evidence.KeyOpener, r audit.RetentionAcceptance, encoded []byte) error {
	if keys == nil || !r.Valid() || len(encoded) < 1 || len(encoded) > 512<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, retentionAcceptanceFormat, r.RootID, r.ID, r, encoded, 256<<10)
}
