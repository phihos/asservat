package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
)

func SealWorkerEnrollment(ctx context.Context, k evidence.KeySealer, e value.WorkerEnrollment) ([]byte, error) {
	if k == nil || !e.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-worker-enrollment/v1", e.Worker.Binding.InstallationID, audit.WorkerEnrollmentKey(e), e, 32<<10)
}
func VerifyWorkerEnrollment(ctx context.Context, k evidence.KeyOpener, e value.WorkerEnrollment, b []byte) error {
	if k == nil || !e.Valid() || len(b) == 0 || len(b) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-worker-enrollment/v1", e.Worker.Binding.InstallationID, audit.WorkerEnrollmentKey(e), e, b, 32<<10)
}
func SealWorkerCertificate(ctx context.Context, k evidence.KeySealer, c audit.WorkerCertificate) ([]byte, error) {
	if k == nil || !c.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-worker-certificate/v1", c.Peer.InstallationID, audit.WorkerCertificateKey(c), c, 64<<10)
}
func VerifyWorkerCertificate(ctx context.Context, k evidence.KeyOpener, c audit.WorkerCertificate, b []byte) error {
	if k == nil || !c.Valid() || len(b) == 0 || len(b) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-worker-certificate/v1", c.Peer.InstallationID, audit.WorkerCertificateKey(c), c, b, 64<<10)
}
