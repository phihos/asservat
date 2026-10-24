package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
)

func SealProjectionWorker(ctx context.Context, k evidence.KeySealer, i analysis.ContextProjectionWorkerIntent) ([]byte, error) {
	if k == nil || !i.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-context-query-worker/v1", i.Query.Scope.RootID, audit.ProjectionWorkerKey(i), i, 64<<10)
}
func VerifyProjectionWorker(ctx context.Context, k evidence.KeyOpener, i analysis.ContextProjectionWorkerIntent, b []byte) error {
	if k == nil || !i.Valid() || len(b) == 0 || len(b) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-context-query-worker/v1", i.Query.Scope.RootID, audit.ProjectionWorkerKey(i), i, b, 64<<10)
}
func SealAcquisitionEnrollment(ctx context.Context, k evidence.KeySealer, e value.AcquisitionEnrollment) ([]byte, error) {
	if k == nil || !e.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-acquisition-enrollment/v1", e.Worker.Binding.InstallationID, audit.AcquisitionEnrollmentKey(e), e, 32<<10)
}
func VerifyAcquisitionEnrollment(ctx context.Context, k evidence.KeyOpener, e value.AcquisitionEnrollment, b []byte) error {
	if k == nil || !e.Valid() || len(b) == 0 || len(b) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-acquisition-enrollment/v1", e.Worker.Binding.InstallationID, audit.AcquisitionEnrollmentKey(e), e, b, 32<<10)
}
func SealAcquisitionCertificate(ctx context.Context, k evidence.KeySealer, c audit.AcquisitionCertificate) ([]byte, error) {
	if k == nil || !c.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-acquisition-certificate/v1", c.Peer.InstallationID, audit.AcquisitionCertificateKey(c), c, 64<<10)
}
func VerifyAcquisitionCertificate(ctx context.Context, k evidence.KeyOpener, c audit.AcquisitionCertificate, b []byte) error {
	if k == nil || !c.Valid() || len(b) == 0 || len(b) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-acquisition-certificate/v1", c.Peer.InstallationID, audit.AcquisitionCertificateKey(c), c, b, 64<<10)
}
