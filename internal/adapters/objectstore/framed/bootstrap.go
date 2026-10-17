package framed

import (
	"context"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

const bootstrapIssueFormat = "asservat-bootstrap-issue-intent-audit/v1"

func SealBootstrapIssue(ctx context.Context, keys evidence.KeySealer, r audit.BootstrapIssue) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, bootstrapIssueFormat, r.Binding.InstallationID, r.ID, r, 64<<10)
}
func VerifyBootstrapIssue(ctx context.Context, keys evidence.KeyOpener, r audit.BootstrapIssue, encoded []byte) error {
	if keys == nil || !r.Valid() || len(encoded) == 0 || len(encoded) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, bootstrapIssueFormat, r.Binding.InstallationID, r.ID, r, encoded, 64<<10)
}
