package objectstore

import (
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

// The same installed object writer, audit key material and put/verify lifecycle
// serve the two closed acquisition purposes. No second provider client exists.
func (s *WorkerEnrollmentAuditObjects) WriteProjectionWorkerIntent(ctx context.Context, i analysis.ContextProjectionWorkerIntent) (audit.Receipt, error) {
	if s == nil || ctx == nil || s.Store == nil || s.Seal == nil || s.Open == nil || !i.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	b, e := framed.SealProjectionWorker(ctx, s.Seal, i)
	if e != nil {
		return audit.Receipt{}, e
	}
	r, e := s.write(ctx, audit.ProjectionWorkerKey(i), b, func(b []byte) error { return framed.VerifyProjectionWorker(ctx, s.Open, i, b) })
	if e != nil {
		return audit.Receipt{}, e
	}
	if !r.ValidProjectionWorker(i) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return r, nil
}
func (s *WorkerEnrollmentAuditObjects) WriteAcquisitionEnrollment(ctx context.Context, e value.AcquisitionEnrollment) (audit.Receipt, error) {
	if s == nil || ctx == nil || s.Store == nil || s.Seal == nil || s.Open == nil || !e.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	b, err := framed.SealAcquisitionEnrollment(ctx, s.Seal, e)
	if err != nil {
		return audit.Receipt{}, err
	}
	r, err := s.write(ctx, audit.AcquisitionEnrollmentKey(e), b, func(b []byte) error { return framed.VerifyAcquisitionEnrollment(ctx, s.Open, e, b) })
	if err != nil {
		return audit.Receipt{}, err
	}
	if !r.ValidAcquisitionEnrollment(e) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return r, nil
}
func (s *WorkerEnrollmentAuditObjects) WriteAcquisitionCertificate(ctx context.Context, c audit.AcquisitionCertificate) (audit.Receipt, error) {
	if s == nil || ctx == nil || s.Store == nil || s.Seal == nil || s.Open == nil || !c.Valid() {
		return audit.Receipt{}, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	b, e := framed.SealAcquisitionCertificate(ctx, s.Seal, c)
	if e != nil {
		return audit.Receipt{}, e
	}
	r, e := s.write(ctx, audit.AcquisitionCertificateKey(c), b, func(b []byte) error { return framed.VerifyAcquisitionCertificate(ctx, s.Open, c, b) })
	if e != nil {
		return audit.Receipt{}, e
	}
	if !r.ValidAcquisitionCertificate(c) {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return r, nil
}
