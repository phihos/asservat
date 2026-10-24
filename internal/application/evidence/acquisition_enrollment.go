package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"crypto/sha256"
	"time"
)

type acquisitionCertificateProgress struct {
	Attempt value.AcquisitionCertificateAttempt
	Signed  *value.WorkerCertificate
	MaySign bool
}

// Only the two concrete parent adapters in this package implement this private
// sequence. It shares protocol ordering, not authorization: each adapter keeps
// its actual typed authority and original record format at the SQL boundary.
type acquisitionEnrollmentFlow interface {
	acquisitionEnrollmentFlow()
	current(context.Context) (value.AcquisitionWorkerProof, error)
	claim(context.Context, value.AcquisitionWorkerProof) (value.AcquisitionEnrollment, audit.Receipt, bool, error)
	enrollmentReceipt(value.AcquisitionEnrollment, audit.Receipt) bool
	writeEnrollment(context.Context, value.AcquisitionEnrollment) (audit.Receipt, error)
	acknowledgeEnrollment(context.Context, value.AcquisitionEnrollment, audit.Receipt) error
	prepare(context.Context, value.AcquisitionWorkerProof) (acquisitionCertificateProgress, error)
	sign(context.Context, value.AcquisitionCertificateAttempt, []byte) (value.WorkerCertificate, error)
	store(context.Context, value.AcquisitionCertificateAttempt, value.WorkerCertificate) error
	certificateReceipt(value.AcquisitionCertificateAttempt, value.WorkerCertificate, audit.Receipt) bool
	readCertificateReceipt(context.Context, value.AcquisitionCertificateAttempt, value.WorkerCertificate) (audit.Receipt, bool, error)
	writeCertificate(context.Context, value.AcquisitionCertificateAttempt, value.WorkerCertificate) (audit.Receipt, error)
	acknowledgeCertificate(context.Context, value.AcquisitionCertificateAttempt, value.WorkerCertificate, audit.Receipt) error
	activate(context.Context, value.AcquisitionWorkerProof, value.AcquisitionCertificateAttempt) (value.WorkerCertificate, error)
}

// Each refusal is labelled with the closed stage it occurred in (ADR-197).
func enrollAcquisition(ctx context.Context, flow acquisitionEnrollmentFlow, csr []byte, key artifact.Digest, now func() time.Time) (_ value.WorkerCertificate, err error) {
	var zero value.WorkerCertificate
	stage := "current"
	defer func() { err = stepped(stage, err) }()
	p, err := flow.current(ctx)
	if err != nil {
		return zero, err
	}
	stage = "claim"
	e, receipt, acknowledged, err := flow.claim(ctx, p)
	if err != nil {
		return zero, err
	}
	if !e.Valid() || e.Worker != p.Worker || e.PublicKeyDigest != key {
		return zero, artifact.ErrIntegrity
	}
	stage = "enrollment-audit"
	if !acknowledged {
		if _, err = flow.current(ctx); err != nil {
			return zero, err
		}
		receipt, err = flow.writeEnrollment(ctx, e)
		if err != nil {
			return zero, err
		}
		if !flow.enrollmentReceipt(e, receipt) {
			return zero, artifact.ErrIntegrity
		}
		if _, err = flow.current(ctx); err != nil {
			return zero, err
		}
		stage = "enrollment-ack"
		if err = flow.acknowledgeEnrollment(ctx, e, receipt); err != nil {
			return zero, err
		}
	} else if !flow.enrollmentReceipt(e, receipt) {
		return zero, artifact.ErrIntegrity
	}
	p, err = flow.current(ctx)
	if err != nil {
		return zero, err
	}
	stage = "prepare"
	progress, err := flow.prepare(ctx, p)
	if err != nil {
		return zero, err
	}
	attempt := progress.Attempt
	if attempt.Enrollment != e || !attempt.Valid(attempt.CheckedAt) {
		return zero, artifact.ErrIntegrity
	}
	if _, err = flow.current(ctx); err != nil {
		return zero, err
	}
	if progress.MaySign {
		if progress.Signed != nil || !attempt.Valid(now()) {
			return zero, artifact.ErrDownloadExpired
		}
		stage = "sign"
		signing, cancel := context.WithDeadline(ctx, attempt.SignBefore)
		c, err := flow.sign(signing, attempt, csr)
		cancel()
		if err != nil {
			return zero, err
		}
		stage = "certificate-check"
		if !attempt.Valid(now()) || !attempt.Matches(c) || artifact.Digest(sha256.Sum256(c.DER)) != c.Peer.Certificate {
			return zero, artifact.ErrIntegrity
		}
		if _, err = flow.current(ctx); err != nil {
			return zero, err
		}
		stage = "store"
		if err = flow.store(ctx, attempt, c); err != nil {
			return zero, err
		}
		progress.Signed = &c
	}
	stage = "signed"
	if progress.Signed == nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	if !attempt.Matches(*progress.Signed) || artifact.Digest(sha256.Sum256(progress.Signed.DER)) != progress.Signed.Peer.Certificate {
		return zero, artifact.ErrIntegrity
	}
	stage = "certificate-receipt"
	r, ok, err := flow.readCertificateReceipt(ctx, attempt, *progress.Signed)
	if err != nil {
		return zero, err
	}
	if !ok {
		if _, err = flow.current(ctx); err != nil {
			return zero, err
		}
		stage = "certificate-audit"
		r, err = flow.writeCertificate(ctx, attempt, *progress.Signed)
		if err != nil {
			return zero, err
		}
		if !flow.certificateReceipt(attempt, *progress.Signed, r) {
			return zero, artifact.ErrIntegrity
		}
		if _, err = flow.current(ctx); err != nil {
			return zero, err
		}
		stage = "certificate-ack"
		if err = flow.acknowledgeCertificate(ctx, attempt, *progress.Signed, r); err != nil {
			return zero, err
		}
	} else if !flow.certificateReceipt(attempt, *progress.Signed, r) {
		return zero, artifact.ErrIntegrity
	}
	p, err = flow.current(ctx)
	if err != nil {
		return zero, err
	}
	stage = "activate"
	c, err := flow.activate(ctx, p, attempt)
	if err != nil {
		return zero, err
	}
	stage = "final"
	if !attempt.Matches(c) || c.Peer != progress.Signed.Peer || artifact.Digest(sha256.Sum256(c.DER)) != c.Peer.Certificate || !p.Valid(now()) || !c.Peer.Valid(now()) || ctx.Err() != nil {
		return zero, artifact.ErrIntegrity
	}
	if _, err = flow.current(ctx); err != nil {
		return zero, err
	}
	return c, nil
}

// The download adapter retains the exact original values in every audit and SQL
// call. Extracting common identity never reconstructs DownloadAuthority or
// changes an existing certificate attempt's serialized digest.
type downloadEnrollmentFlow struct {
	service    *WorkerEnrollmentCoordinator
	check      func() (value.WorkerEnrollmentProof, error)
	proof      value.WorkerEnrollmentProof
	enrollment value.WorkerEnrollment
	attempt    value.WorkerCertificateAttempt
}

func (*downloadEnrollmentFlow) acquisitionEnrollmentFlow() {}
func (f *downloadEnrollmentFlow) current(ctx context.Context) (value.AcquisitionWorkerProof, error) {
	var err error
	f.proof, err = f.check()
	return f.proof.Acquisition(), err
}
func (f *downloadEnrollmentFlow) claim(ctx context.Context, p value.AcquisitionWorkerProof) (value.AcquisitionEnrollment, audit.Receipt, bool, error) {
	if p != f.proof.Acquisition() {
		return value.AcquisitionEnrollment{}, audit.Receipt{}, false, artifact.ErrIntegrity
	}
	e, r, ok, err := f.service.Ledger.ClaimWorkerEnrollment(ctx, f.proof)
	if err == nil && !e.Valid() {
		return value.AcquisitionEnrollment{}, audit.Receipt{}, false, artifact.ErrIntegrity
	}
	f.enrollment = e
	return e.Acquisition(), r, ok, err
}
func (f *downloadEnrollmentFlow) enrollmentReceipt(e value.AcquisitionEnrollment, r audit.Receipt) bool {
	return e == f.enrollment.Acquisition() && r.ValidWorkerEnrollment(f.enrollment)
}
func (f *downloadEnrollmentFlow) writeEnrollment(ctx context.Context, e value.AcquisitionEnrollment) (audit.Receipt, error) {
	if e != f.enrollment.Acquisition() {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return f.service.Audit.WriteWorkerEnrollment(ctx, f.enrollment)
}
func (f *downloadEnrollmentFlow) acknowledgeEnrollment(ctx context.Context, e value.AcquisitionEnrollment, r audit.Receipt) error {
	if !f.enrollmentReceipt(e, r) {
		return artifact.ErrIntegrity
	}
	return f.service.Acknowledgements.AcknowledgeWorkerEnrollment(ctx, f.enrollment, r)
}
func (f *downloadEnrollmentFlow) prepare(ctx context.Context, p value.AcquisitionWorkerProof) (acquisitionCertificateProgress, error) {
	if p != f.proof.Acquisition() {
		return acquisitionCertificateProgress{}, artifact.ErrIntegrity
	}
	progress, err := f.service.Ledger.PrepareWorkerCertificate(ctx, f.proof)
	if err == nil && !progress.Attempt.Valid(progress.Attempt.CheckedAt) {
		return acquisitionCertificateProgress{}, artifact.ErrIntegrity
	}
	f.attempt = progress.Attempt
	return acquisitionCertificateProgress{Attempt: progress.Attempt.Acquisition(), Signed: progress.Signed, MaySign: progress.MaySign}, err
}
func (f *downloadEnrollmentFlow) sign(ctx context.Context, a value.AcquisitionCertificateAttempt, csr []byte) (value.WorkerCertificate, error) {
	if a != f.attempt.Acquisition() {
		return value.WorkerCertificate{}, artifact.ErrIntegrity
	}
	return f.service.Issuer.SignWorkerCertificate(ctx, f.attempt, csr)
}
func (f *downloadEnrollmentFlow) store(ctx context.Context, a value.AcquisitionCertificateAttempt, c value.WorkerCertificate) error {
	if a != f.attempt.Acquisition() {
		return artifact.ErrIntegrity
	}
	return f.service.Ledger.StoreWorkerCertificate(ctx, f.attempt, c)
}
func (f *downloadEnrollmentFlow) certificateReceipt(a value.AcquisitionCertificateAttempt, c value.WorkerCertificate, r audit.Receipt) bool {
	return a == f.attempt.Acquisition() && r.ValidWorkerCertificate(audit.WorkerCertificate{Attempt: f.attempt, Peer: c.Peer})
}
func (f *downloadEnrollmentFlow) readCertificateReceipt(ctx context.Context, a value.AcquisitionCertificateAttempt, c value.WorkerCertificate) (audit.Receipt, bool, error) {
	if a != f.attempt.Acquisition() {
		return audit.Receipt{}, false, artifact.ErrIntegrity
	}
	return f.service.Acknowledgements.ReadWorkerCertificateReceipt(ctx, audit.WorkerCertificate{Attempt: f.attempt, Peer: c.Peer})
}
func (f *downloadEnrollmentFlow) writeCertificate(ctx context.Context, a value.AcquisitionCertificateAttempt, c value.WorkerCertificate) (audit.Receipt, error) {
	if a != f.attempt.Acquisition() {
		return audit.Receipt{}, artifact.ErrIntegrity
	}
	return f.service.Audit.WriteWorkerCertificate(ctx, audit.WorkerCertificate{Attempt: f.attempt, Peer: c.Peer})
}
func (f *downloadEnrollmentFlow) acknowledgeCertificate(ctx context.Context, a value.AcquisitionCertificateAttempt, c value.WorkerCertificate, r audit.Receipt) error {
	if !f.certificateReceipt(a, c, r) {
		return artifact.ErrIntegrity
	}
	return f.service.Acknowledgements.AcknowledgeWorkerCertificate(ctx, audit.WorkerCertificate{Attempt: f.attempt, Peer: c.Peer}, r)
}
func (f *downloadEnrollmentFlow) activate(ctx context.Context, p value.AcquisitionWorkerProof, a value.AcquisitionCertificateAttempt) (value.WorkerCertificate, error) {
	if p != f.proof.Acquisition() || a != f.attempt.Acquisition() {
		return value.WorkerCertificate{}, artifact.ErrIntegrity
	}
	return f.service.Activation.ActivateWorkerCertificate(ctx, f.proof, f.attempt)
}
