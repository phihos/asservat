package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
)

func SealOperationIntent(ctx context.Context, keys evidence.KeySealer, r audit.OperationIntent) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, operationRecordFormat("intent", r), r.RootID, r.ID, r, operationRecordLimit("intent", r))
}
func VerifyOperationIntent(ctx context.Context, keys evidence.KeyOpener, r audit.OperationIntent, b []byte) error {
	if keys == nil || !r.Valid() || len(b) == 0 || len(b) > audit.OperationCipherLimit {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, operationRecordFormat("intent", r), r.RootID, r.ID, r, b, operationRecordLimit("intent", r))
}
func SealOperationOutcome(ctx context.Context, keys evidence.KeySealer, r audit.OperationOutcome) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, operationRecordFormat("outcome", r.Intent), r.Intent.RootID, r.Intent.ID, r, operationRecordLimit("outcome", r.Intent))
}
func VerifyOperationOutcome(ctx context.Context, keys evidence.KeyOpener, r audit.OperationOutcome, b []byte) error {
	if keys == nil || !r.Valid() || len(b) == 0 || len(b) > audit.OperationCipherLimit {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, operationRecordFormat("outcome", r.Intent), r.Intent.RootID, r.Intent.ID, r, b, operationRecordLimit("outcome", r.Intent))
}

func operationAuditFormat(phase string, healthy bool) string {
	version := "/v1"
	if healthy {
		version = "/v2"
	}
	return "asservat-operation-" + phase + version
}

func operationRecordFormat(phase string, in audit.OperationIntent) string {
	return operationAuditFormat(phase, in.Lifecycle != nil)
}
func operationRecordLimit(phase string, in audit.OperationIntent) int {
	if phase == "intent" {
		return 8 << 10
	}
	return 16 << 10
}
