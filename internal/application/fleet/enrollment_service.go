package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	auditport "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

type EnrollmentProofVerifier interface {
	EnrollmentKey([]byte) (artifact.Digest, error)
}

// ConnectorEnrollment composes already reviewed bootstrap claims. Bootstrap
// issuance/admin approval, ingress rate limits and private-key custody belong
// to their own boundaries. It never returns an unaudited/inactive certificate.
type ConnectorEnrollment struct {
	Proof              EnrollmentProofVerifier
	Claims             EnrollmentLedger
	ClaimAudits        auditport.EnrollmentClaimLedger
	ClaimObjects       auditport.EnrollmentClaimWriter
	Signing            SigningLedger
	Issuer             CertificateIssuer
	CertificateAudits  auditport.EnrollmentCertificateLedger
	CertificateObjects auditport.EnrollmentCertificateWriter
	Activation         EnrollmentActivator
	Now                func() time.Time
}

func (s ConnectorEnrollment) Enroll(ctx context.Context, c value.EnrollmentClaim, csr []byte) (value.IssuedCertificate, error) {
	var empty value.IssuedCertificate
	if s.Proof == nil || s.Claims == nil || s.ClaimAudits == nil || s.ClaimObjects == nil || s.Signing == nil || s.Issuer == nil || s.CertificateAudits == nil || s.CertificateObjects == nil || s.Activation == nil || s.Now == nil {
		return empty, value.ErrUnavailable
	}
	if !c.Valid() || len(csr) == 0 || len(csr) > 8192 {
		return empty, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key, err := s.Proof.EnrollmentKey(csr)
	if err != nil || key != c.PublicKeyDigest {
		return empty, value.ErrDenied
	}
	enrollment, err := s.Claims.ClaimConnector(ctx, c)
	if err != nil {
		return empty, err
	}
	if enrollment.PublicKeyDigest != key {
		return empty, value.ErrDenied
	}
	if _, err = acknowledgeEnrollmentClaim(ctx, s.ClaimAudits, s.ClaimObjects, c.InstallationID, c.BootstrapID, enrollment); err != nil {
		return empty, err
	}
	progress, err := s.Signing.PrepareConnector(ctx, c)
	if err != nil {
		return empty, err
	}
	a := progress.Attempt
	e := a.Permit.Enrollment
	if e.Binding != enrollment.Binding || e.PublicKeyDigest != key || e.BootstrapID != c.BootstrapID || !e.ClaimedAt.Equal(enrollment.ClaimedAt) || !e.NotAfter.Equal(enrollment.NotAfter) {
		return empty, value.ErrDenied
	}
	if progress.MaySign {
		if progress.Signed != nil || progress.Active || !a.Valid(s.Now()) {
			return empty, value.ErrDenied
		}
		issued, err := s.Issuer.SignConnector(ctx, a.Permit, csr)
		if err != nil {
			return empty, err
		}
		if !a.Valid(s.Now()) || !a.MatchesIssued(issued) || artifact.Digest(sha256.Sum256(issued.DER)) != issued.Certificate.Digest {
			return empty, value.ErrDenied
		}
		if err = s.Signing.StoreConnectorCertificate(ctx, a, issued); err != nil {
			return empty, err
		}
		progress.Signed = &issued
	}
	if progress.Signed == nil {
		return empty, value.ErrPending
	}
	if !a.MatchesIssued(*progress.Signed) || artifact.Digest(sha256.Sum256(progress.Signed.DER)) != progress.Signed.Certificate.Digest {
		return empty, value.ErrDenied
	}
	certificateRecord := audit.EnrollmentCertificate{Attempt: a, Certificate: progress.Signed.Certificate}
	if !certificateRecord.Valid() {
		return empty, value.ErrDenied
	}
	certificateReceipt, err := s.CertificateObjects.WriteEnrollmentCertificate(ctx, certificateRecord)
	if err != nil {
		return empty, err
	}
	if !certificateReceipt.ValidEnrollmentCertificate(c.InstallationID, a.ID) {
		return empty, value.ErrDenied
	}
	if err = s.CertificateAudits.AcknowledgeEnrollmentCertificate(ctx, certificateRecord, certificateReceipt); err != nil {
		return empty, err
	}
	return s.Activation.ActivateConnector(ctx, c, a.ID)
}

// acknowledgeEnrollmentClaim writes and acknowledges the encrypted claim audit
// of a claimed bootstrap and returns the audited record's digest, the value
// the ledger stores as the claim audit digest.
func acknowledgeEnrollmentClaim(ctx context.Context, audits auditport.EnrollmentClaimLedger, objects auditport.EnrollmentClaimWriter, installation, bootstrap string, enrollment value.Enrollment) (artifact.Digest, error) {
	record, err := audits.ReadEnrollmentClaim(ctx, installation, bootstrap)
	if err != nil {
		return artifact.Digest{}, err
	}
	if !record.Valid() || record.Binding != enrollment.Binding || record.PublicKeyDigest != enrollment.PublicKeyDigest || record.BootstrapID != bootstrap || record.Binding.InstallationID != installation || !record.ClaimedAt.Equal(enrollment.ClaimedAt) || !record.NotAfter.Equal(enrollment.NotAfter) {
		return artifact.Digest{}, value.ErrDenied
	}
	receipt, err := objects.WriteEnrollmentClaim(ctx, record)
	if err != nil {
		return artifact.Digest{}, err
	}
	if !receipt.ValidEnrollmentClaim(installation, bootstrap) {
		return artifact.Digest{}, value.ErrDenied
	}
	if err = audits.AcknowledgeEnrollmentClaim(ctx, record, receipt); err != nil {
		return artifact.Digest{}, err
	}
	b, err := json.Marshal(record)
	if err != nil {
		return artifact.Digest{}, value.ErrDenied
	}
	return sha256.Sum256(b), nil
}
