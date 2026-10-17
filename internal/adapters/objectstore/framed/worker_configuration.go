package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
)

func SealWorkerConfiguration(ctx context.Context, k evidence.KeySealer, c value.DownloadWorkerConfiguration) ([]byte, error) {
	if k == nil || !c.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-download-worker-configuration/v1", c.Profile.InstallationID, audit.WorkerConfigurationAuditKey(c), c, 16<<10)
}
func VerifyWorkerConfiguration(ctx context.Context, k evidence.KeyOpener, c value.DownloadWorkerConfiguration, b []byte) error {
	if k == nil || !c.Valid() || len(b) == 0 || len(b) > 64<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-download-worker-configuration/v1", c.Profile.InstallationID, audit.WorkerConfigurationAuditKey(c), c, b, 16<<10)
}
