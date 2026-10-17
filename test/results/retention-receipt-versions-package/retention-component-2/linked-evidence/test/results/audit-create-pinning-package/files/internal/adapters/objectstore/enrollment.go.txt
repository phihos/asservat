package objectstore

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

type EnrollmentClaimObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ auditapp.EnrollmentClaimWriter = (*EnrollmentClaimObjects)(nil)

type EnrollmentCertificateObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ auditapp.EnrollmentCertificateWriter = (*EnrollmentCertificateObjects)(nil)

func (a *EnrollmentCertificateObjects) WriteEnrollmentCertificate(ctx context.Context, r audit.EnrollmentCertificate) (audit.Receipt, error) {
	var out audit.Receipt
	if a.Store == nil || a.Seal == nil || a.Open == nil || !r.Valid() {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key := audit.EnrollmentCertificateKey(r.Certificate.Binding.InstallationID, r.Attempt.ID)
	cipher, err := framed.SealEnrollmentCertificate(ctx, a.Seal, r)
	if err != nil {
		return out, err
	}
	object, body, err := a.Store.putControlAudit(ctx, key, cipher, 128<<10)
	if err != nil {
		return out, err
	}
	if err = framed.VerifyEnrollmentCertificate(ctx, a.Open, r, body); err != nil {
		return out, err
	}
	out = audit.Receipt{Key: key, Version: object.VersionID, ETag: object.ETag, Bytes: object.Bytes, SHA256: object.SHA256}
	if !out.ValidEnrollmentCertificate(r.Certificate.Binding.InstallationID, r.Attempt.ID) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return out, nil
}

func (a *EnrollmentClaimObjects) WriteEnrollmentClaim(ctx context.Context, r audit.EnrollmentClaim) (audit.Receipt, error) {
	var out audit.Receipt
	if a.Store == nil || a.Seal == nil || a.Open == nil || !r.Valid() {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key := audit.EnrollmentClaimKey(r.Binding.InstallationID, r.BootstrapID)
	cipher, err := framed.SealEnrollmentClaim(ctx, a.Seal, r)
	if err != nil {
		return out, err
	}
	object, body, err := a.Store.putControlAudit(ctx, key, cipher, 128<<10)
	if err != nil {
		return out, err
	}
	if err = framed.VerifyEnrollmentClaim(ctx, a.Open, r, body); err != nil {
		return out, err
	}
	out = audit.Receipt{Key: key, Version: object.VersionID, ETag: object.ETag, Bytes: object.Bytes, SHA256: object.SHA256}
	if !out.ValidEnrollmentClaim(r.Binding.InstallationID, r.BootstrapID) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return out, nil
}
