package framed

import (
	"context"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

func SealClusterBootstrap(ctx context.Context, k evidence.KeySealer, r audit.ClusterBootstrap) ([]byte, error) {
	if k == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-cluster-bootstrap/v1", r.InstallationID, audit.ClusterBootstrapAuditKey(r), r, 16<<10)
}
func VerifyClusterBootstrap(ctx context.Context, k evidence.KeyOpener, r audit.ClusterBootstrap, b []byte) error {
	if k == nil || !r.Valid() || len(b) == 0 || len(b) > 64<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-cluster-bootstrap/v1", r.InstallationID, audit.ClusterBootstrapAuditKey(r), r, b, 16<<10)
}
