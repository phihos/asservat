package framed

import (
	"context"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

const policyAcceptanceFormat = "asservat-policy-acceptance-audit/v1"

func SealPolicyAcceptance(ctx context.Context, keys evidence.KeySealer, r audit.PolicyAcceptance) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, policyAcceptanceFormat, r.RootID, r.ID, r, 64<<10)
}
func VerifyPolicyAcceptance(ctx context.Context, keys evidence.KeyOpener, r audit.PolicyAcceptance, encoded []byte) error {
	if keys == nil || !r.Valid() || len(encoded) == 0 || len(encoded) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, policyAcceptanceFormat, r.RootID, r.ID, r, encoded, 64<<10)
}
