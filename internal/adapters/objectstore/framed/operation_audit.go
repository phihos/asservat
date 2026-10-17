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
	if r.Name == audit.CaptureOperationName {
		return sealCaptureOperation(ctx, keys, operationRecordFormat("intent", r), r.RootID, r.ID, r)
	}
	return sealControlAudit(ctx, keys, operationRecordFormat("intent", r), r.RootID, r.ID, r, operationRecordLimit("intent", r))
}
func VerifyOperationIntent(ctx context.Context, keys evidence.KeyOpener, r audit.OperationIntent, b []byte) error {
	if keys == nil || !r.Valid() || len(b) == 0 || len(b) > audit.OperationCipherLimit {
		return artifact.ErrInvalid
	}
	if r.Name == audit.CaptureOperationName {
		return verifyCaptureOperation(ctx, keys, operationRecordFormat("intent", r), r.RootID, r.ID, r, b, 16<<10)
	}
	return verifyControlAudit(ctx, keys, operationRecordFormat("intent", r), r.RootID, r.ID, r, b, operationRecordLimit("intent", r))
}
func SealOperationOutcome(ctx context.Context, keys evidence.KeySealer, r audit.OperationOutcome) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	if r.Intent.Name == audit.CaptureOperationName {
		return sealCaptureOperation(ctx, keys, operationRecordFormat("outcome", r.Intent), r.Intent.RootID, r.Intent.ID, r)
	}
	return sealControlAudit(ctx, keys, operationRecordFormat("outcome", r.Intent), r.Intent.RootID, r.Intent.ID, r, operationRecordLimit("outcome", r.Intent))
}
func VerifyOperationOutcome(ctx context.Context, keys evidence.KeyOpener, r audit.OperationOutcome, b []byte) error {
	if keys == nil || !r.Valid() || len(b) == 0 || len(b) > audit.OperationCipherLimit {
		return artifact.ErrInvalid
	}
	if r.Intent.Name == audit.CaptureOperationName {
		return verifyCaptureOperation(ctx, keys, operationRecordFormat("outcome", r.Intent), r.Intent.RootID, r.Intent.ID, r, b, 24<<10)
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

// The capture payload is an explicit private format. Other encoded records and
// their byte ceilings are preserved exactly; this branch cannot promote them.
func operationRecordFormat(phase string, in audit.OperationIntent) string {
	if in.Name == audit.CaptureOperationName {
		return "asservat-capture-" + phase + "/v1"
	}
	return operationAuditFormat(phase, in.Lifecycle != nil)
}
func operationRecordLimit(phase string, in audit.OperationIntent) int {
	if in.Name == audit.CaptureOperationName {
		if phase == "intent" {
			return 16 << 10
		}
		return 24 << 10
	}
	if phase == "intent" {
		return 8 << 10
	}
	return 16 << 10
}
