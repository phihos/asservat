package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

type WorkerEnrollmentAuditObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}

var _ app.WorkerEnrollmentWriter = (*WorkerEnrollmentAuditObjects)(nil)

func (s *WorkerEnrollmentAuditObjects) WriteWorkerEnrollment(ctx context.Context, e value.WorkerEnrollment) (audit.Receipt, error) {
	if s == nil || ctx == nil || s.Store == nil || s.Seal == nil || s.Open == nil || !e.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	b, err := framed.SealWorkerEnrollment(ctx, s.Seal, e)
	if err != nil {
		return audit.Receipt{}, err
	}
	r, err := s.write(ctx, audit.WorkerEnrollmentKey(e), b, func(b []byte) error { return framed.VerifyWorkerEnrollment(ctx, s.Open, e, b) })
	if err != nil {
		return audit.Receipt{}, err
	}
	if !r.ValidWorkerEnrollment(e) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return r, nil
}
func (s *WorkerEnrollmentAuditObjects) WriteWorkerCertificate(ctx context.Context, c audit.WorkerCertificate) (audit.Receipt, error) {
	if s == nil || ctx == nil || s.Store == nil || s.Seal == nil || s.Open == nil || !c.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	b, err := framed.SealWorkerCertificate(ctx, s.Seal, c)
	if err != nil {
		return audit.Receipt{}, err
	}
	r, err := s.write(ctx, audit.WorkerCertificateKey(c), b, func(b []byte) error { return framed.VerifyWorkerCertificate(ctx, s.Open, c, b) })
	if err != nil {
		return audit.Receipt{}, err
	}
	if !r.ValidWorkerCertificate(c) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return r, nil
}
func (s *WorkerEnrollmentAuditObjects) write(ctx context.Context, key string, b []byte, verify func([]byte) error) (audit.Receipt, error) {
	o, raw, e := s.Store.putControlAudit(ctx, key, b, 128<<10)
	if e != nil {
		return audit.Receipt{}, e
	}
	if e = verify(raw); e != nil {
		return audit.Receipt{}, e
	}
	return audit.Receipt{Key: key, Version: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}, nil
}
