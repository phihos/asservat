package framed

import (
	"context"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

const ownerConfigurationEpochAuditFormat = "asservat-owner-configuration-epoch-audit/v1"

// SealOwnerConfigurationEpoch encrypts the complete original epoch snapshot.
// It supplies neither a write permit nor current epoch/source acceptance. The
// caller must spend its original bounded claim before this wrap-only operation.
// Legacy configuration audit bytes and their encryption context stay separate.
func SealOwnerConfigurationEpoch(ctx context.Context, keys evidence.KeySealer, record audit.OwnerConfigurationEpoch) ([]byte, error) {
	if keys == nil || !record.Valid() {
		return nil, artifact.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encoded, err := sealControlAudit(ctx, keys, ownerConfigurationEpochAuditFormat, record.Epoch.Reserve.InstallationID, audit.OwnerConfigurationEpochKey(record), record, 64<<10)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > 128<<10 || int64(len(encoded)) > record.Epoch.Reserve.Policy.PerEpoch.CiphertextBytes {
		return nil, artifact.ErrLimit
	}
	return encoded, nil
}

// VerifyOwnerConfigurationEpoch authenticates the exact expected snapshot.
// Expected facts come from the original independently accepted claim, never
// decoded untrusted content. Historical verification does not make an expired
// epoch selectable, release capacity, or replace immutable version checks.
func VerifyOwnerConfigurationEpoch(ctx context.Context, keys evidence.KeyOpener, record audit.OwnerConfigurationEpoch, encoded []byte) error {
	if keys == nil || !record.Valid() || len(encoded) == 0 || len(encoded) > 128<<10 || int64(len(encoded)) > record.Epoch.Reserve.Policy.PerEpoch.CiphertextBytes {
		return artifact.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyControlAudit(ctx, keys, ownerConfigurationEpochAuditFormat, record.Epoch.Reserve.InstallationID, audit.OwnerConfigurationEpochKey(record), record, encoded, 64<<10); err != nil {
		return err
	}
	return ctx.Err()
}
