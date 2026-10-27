package evidence

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

// Identity effects use the admitted query parent, current configuration/recovery
// and original worker lifetime. They do not grant ReadApproved or consume a
// human request; query/native/key effects keep their independent current gates.
type ProjectionEnrollmentEffects interface {
	ClaimAcquisitionEnrollment(context.Context, value.AcquisitionWorkerProof) (value.AcquisitionEnrollment, audit.Receipt, bool, error)
	AcknowledgeAcquisitionEnrollment(context.Context, value.AcquisitionEnrollment, audit.Receipt) error
	PrepareAcquisitionCertificate(context.Context, value.AcquisitionWorkerProof) (value.AcquisitionCertificateProgress, error)
	StoreAcquisitionCertificate(context.Context, value.AcquisitionCertificateAttempt, value.WorkerCertificate) error
	ReadAcquisitionCertificateReceipt(context.Context, audit.AcquisitionCertificate) (audit.Receipt, bool, error)
	AcknowledgeAcquisitionCertificate(context.Context, audit.AcquisitionCertificate, audit.Receipt) error
	ActivateAcquisitionCertificate(context.Context, value.AcquisitionWorkerProof, value.AcquisitionCertificateAttempt) (value.WorkerCertificate, error)
}
type AcquisitionCertificateIssuer interface {
	SignAcquisitionCertificate(context.Context, value.AcquisitionCertificateAttempt, []byte) (value.WorkerCertificate, error)
}

type ProjectionEnrollmentCoordinator struct {
	CSR    WorkerCSRVerifier
	Proofs AcquisitionEnrollmentProofReader
	Ledger ProjectionEnrollmentEffects
	Audit  auditapp.AcquisitionEnrollmentWriter
	Issuer AcquisitionCertificateIssuer
	Now    func() time.Time
}

func (s *ProjectionEnrollmentCoordinator) EnrollProjection(ctx context.Context, parent value.AcquisitionParent, worker string, csr []byte) (value.WorkerCertificate, error) {
	return s.enrollProjection(ctx, ctx, parent, worker, csr)
}

func (s *ProjectionEnrollmentCoordinator) enrollProjection(ctx, owner context.Context, parent value.AcquisitionParent, worker string, csr []byte) (value.WorkerCertificate, error) {
	var zero value.WorkerCertificate
	if s == nil || ctx == nil || owner == nil || owner.Err() != nil || ctx.Err() != nil || s.CSR == nil || s.Proofs == nil || s.Ledger == nil || s.Audit == nil || s.Issuer == nil || s.Now == nil || !parent.Valid() || parent.Purpose != value.AcquisitionProjection || !value.UUID(worker) || len(csr) < 1 || len(csr) > 8192 {
		return zero, query.ErrUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key, e := s.CSR.EnrollmentKey(csr)
	if e != nil || key == (artifact.Digest{}) || owner.Err() != nil {
		return zero, collapsed("csr", query.ErrUnavailable, e)
	}
	p, e := s.Proofs.ReadAcquisitionEnrollmentProof(call, parent, worker, key)
	if e != nil || !p.Valid(s.Now()) || p.Worker.Intent.Parent != parent || p.Worker.Intent.ID != worker || p.PublicKeyDigest != key || call.Err() != nil || owner.Err() != nil {
		return zero, collapsed("proof", query.ErrUnavailable, e)
	}
	proofCall, stop := context.WithDeadline(call, p.FreshUntil)
	defer stop()
	f := &projectionEnrollmentFlow{service: s, proof: p, check: func() bool {
		return owner.Err() == nil && ctx.Err() == nil && call.Err() == nil && proofCall.Err() == nil && p.Valid(s.Now())
	}}
	return enrollAcquisition(proofCall, f, csr, key, s.Now)
}

type projectionEnrollmentFlow struct {
	service *ProjectionEnrollmentCoordinator
	proof   value.AcquisitionWorkerProof
	check   func() bool
}

func (*projectionEnrollmentFlow) acquisitionEnrollmentFlow() {}
func (f *projectionEnrollmentFlow) current(ctx context.Context) (value.AcquisitionWorkerProof, error) {
	if ctx == nil || ctx.Err() != nil || !f.check() {
		return value.AcquisitionWorkerProof{}, query.ErrUnavailable
	}
	return f.proof, nil
}
func (f *projectionEnrollmentFlow) claim(ctx context.Context, p value.AcquisitionWorkerProof) (value.AcquisitionEnrollment, audit.Receipt, bool, error) {
	return f.service.Ledger.ClaimAcquisitionEnrollment(ctx, p)
}
func (f *projectionEnrollmentFlow) enrollmentReceipt(e value.AcquisitionEnrollment, r audit.Receipt) bool {
	return r.ValidAcquisitionEnrollment(e)
}
func (f *projectionEnrollmentFlow) writeEnrollment(ctx context.Context, e value.AcquisitionEnrollment) (audit.Receipt, error) {
	return f.service.Audit.WriteAcquisitionEnrollment(ctx, e)
}
func (f *projectionEnrollmentFlow) acknowledgeEnrollment(ctx context.Context, e value.AcquisitionEnrollment, r audit.Receipt) error {
	return f.service.Ledger.AcknowledgeAcquisitionEnrollment(ctx, e, r)
}
func (f *projectionEnrollmentFlow) prepare(ctx context.Context, p value.AcquisitionWorkerProof) (acquisitionCertificateProgress, error) {
	v, e := f.service.Ledger.PrepareAcquisitionCertificate(ctx, p)
	return acquisitionCertificateProgress{Attempt: v.Attempt, Signed: v.Signed, MaySign: v.MaySign}, e
}
func (f *projectionEnrollmentFlow) sign(ctx context.Context, a value.AcquisitionCertificateAttempt, csr []byte) (value.WorkerCertificate, error) {
	return f.service.Issuer.SignAcquisitionCertificate(ctx, a, csr)
}
func (f *projectionEnrollmentFlow) store(ctx context.Context, a value.AcquisitionCertificateAttempt, c value.WorkerCertificate) error {
	return f.service.Ledger.StoreAcquisitionCertificate(ctx, a, c)
}
func (f *projectionEnrollmentFlow) certificateReceipt(a value.AcquisitionCertificateAttempt, c value.WorkerCertificate, r audit.Receipt) bool {
	return r.ValidAcquisitionCertificate(audit.AcquisitionCertificate{Attempt: a, Peer: c.Peer})
}
func (f *projectionEnrollmentFlow) readCertificateReceipt(ctx context.Context, a value.AcquisitionCertificateAttempt, c value.WorkerCertificate) (audit.Receipt, bool, error) {
	return f.service.Ledger.ReadAcquisitionCertificateReceipt(ctx, audit.AcquisitionCertificate{Attempt: a, Peer: c.Peer})
}
func (f *projectionEnrollmentFlow) writeCertificate(ctx context.Context, a value.AcquisitionCertificateAttempt, c value.WorkerCertificate) (audit.Receipt, error) {
	return f.service.Audit.WriteAcquisitionCertificate(ctx, audit.AcquisitionCertificate{Attempt: a, Peer: c.Peer})
}
func (f *projectionEnrollmentFlow) acknowledgeCertificate(ctx context.Context, a value.AcquisitionCertificateAttempt, c value.WorkerCertificate, r audit.Receipt) error {
	return f.service.Ledger.AcknowledgeAcquisitionCertificate(ctx, audit.AcquisitionCertificate{Attempt: a, Peer: c.Peer}, r)
}
func (f *projectionEnrollmentFlow) activate(ctx context.Context, p value.AcquisitionWorkerProof, a value.AcquisitionCertificateAttempt) (value.WorkerCertificate, error) {
	return f.service.Ledger.ActivateAcquisitionCertificate(ctx, p, a)
}
