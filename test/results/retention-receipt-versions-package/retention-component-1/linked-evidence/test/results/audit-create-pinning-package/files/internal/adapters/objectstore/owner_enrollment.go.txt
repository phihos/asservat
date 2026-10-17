package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
	"time"
)

type OwnerEnrollmentAuditObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ app.OwnerEnrollmentWriter = (*OwnerEnrollmentAuditObjects)(nil)

func (s *OwnerEnrollmentAuditObjects) WriteOwnerEnrollment(ctx context.Context, e value.OwnerEnrollment) (audit.Receipt, error) {
	if s == nil || ctx == nil || s.Store == nil || s.Seal == nil || s.Open == nil || !e.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	b, err := framed.SealOwnerEnrollment(ctx, s.Seal, e)
	if err != nil {
		return audit.Receipt{}, err
	}
	r, err := s.write(ctx, audit.OwnerEnrollmentKey(e), b, func(b []byte) error { return framed.VerifyOwnerEnrollment(ctx, s.Open, e, b) })
	if err != nil {
		return audit.Receipt{}, err
	}
	if !r.ValidOwnerEnrollment(e) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return r, nil
}
func (s *OwnerEnrollmentAuditObjects) WriteOwnerCertificate(ctx context.Context, c audit.OwnerCertificate) (audit.Receipt, error) {
	if s == nil || ctx == nil || s.Store == nil || s.Seal == nil || s.Open == nil || !c.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	b, err := framed.SealOwnerCertificate(ctx, s.Seal, c)
	if err != nil {
		return audit.Receipt{}, err
	}
	r, err := s.write(ctx, audit.OwnerCertificateKey(c), b, func(b []byte) error { return framed.VerifyOwnerCertificate(ctx, s.Open, c, b) })
	if err != nil {
		return audit.Receipt{}, err
	}
	if !r.ValidOwnerCertificate(c) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return r, nil
}
func (s *OwnerEnrollmentAuditObjects) write(ctx context.Context, key string, b []byte, verify func([]byte) error) (audit.Receipt, error) {
	o, raw, e := s.Store.putControlAudit(ctx, key, b, 128<<10)
	if e != nil {
		return audit.Receipt{}, e
	}
	if e = verify(raw); e != nil {
		return audit.Receipt{}, e
	}
	return audit.Receipt{Key: key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}, nil
}
