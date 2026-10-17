package framed

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
)

func SealOwnerEnrollment(ctx context.Context, k evidence.KeySealer, e value.OwnerEnrollment) ([]byte, error) {
	if k == nil || !e.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-owner-enrollment/v1", e.Binding.InstallationID, audit.OwnerEnrollmentKey(e), e, 32<<10)
}
func VerifyOwnerEnrollment(ctx context.Context, k evidence.KeyOpener, e value.OwnerEnrollment, b []byte) error {
	if k == nil || !e.Valid() || len(b) == 0 || len(b) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-owner-enrollment/v1", e.Binding.InstallationID, audit.OwnerEnrollmentKey(e), e, b, 32<<10)
}
func SealOwnerCertificate(ctx context.Context, k evidence.KeySealer, c audit.OwnerCertificate) ([]byte, error) {
	if k == nil || !c.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, k, "asservat-owner-certificate/v1", c.Certificate.Binding.InstallationID, audit.OwnerCertificateKey(c), c, 64<<10)
}
func VerifyOwnerCertificate(ctx context.Context, k evidence.KeyOpener, c audit.OwnerCertificate, b []byte) error {
	if k == nil || !c.Valid() || len(b) == 0 || len(b) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, k, "asservat-owner-certificate/v1", c.Certificate.Binding.InstallationID, audit.OwnerCertificateKey(c), c, b, 64<<10)
}
