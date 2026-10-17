package framed

import (
	"context"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

const enrollmentClaimFormat = "asservat-enrollment-claim-audit/v1"
const enrollmentCertificateFormat = "asservat-enrollment-certificate-audit/v1"

func SealEnrollmentCertificate(ctx context.Context, keys evidence.KeySealer, r audit.EnrollmentCertificate) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, enrollmentCertificateFormat, r.Certificate.Binding.InstallationID, r.Attempt.ID, r, 64<<10)
}
func VerifyEnrollmentCertificate(ctx context.Context, keys evidence.KeyOpener, r audit.EnrollmentCertificate, encoded []byte) error {
	if keys == nil || !r.Valid() || len(encoded) == 0 || len(encoded) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, enrollmentCertificateFormat, r.Certificate.Binding.InstallationID, r.Attempt.ID, r, encoded, 64<<10)
}

func SealEnrollmentClaim(ctx context.Context, keys evidence.KeySealer, r audit.EnrollmentClaim) ([]byte, error) {
	if keys == nil || !r.Valid() {
		return nil, artifact.ErrInvalid
	}
	return sealControlAudit(ctx, keys, enrollmentClaimFormat, r.Binding.InstallationID, r.BootstrapID, r, 64<<10)
}
func VerifyEnrollmentClaim(ctx context.Context, keys evidence.KeyOpener, r audit.EnrollmentClaim, encoded []byte) error {
	if keys == nil || !r.Valid() || len(encoded) == 0 || len(encoded) > 128<<10 {
		return artifact.ErrInvalid
	}
	return verifyControlAudit(ctx, keys, enrollmentClaimFormat, r.Binding.InstallationID, r.BootstrapID, r, encoded, 64<<10)
}
