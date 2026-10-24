package evidence

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

type WorkerEnrollmentBindings interface {
	ReadDownloadWorkerEnrollment(context.Context, string, string) (value.DownloadWorkerIdentity, error)
}
type WorkerEnrollmentProofReader interface {
	ReadWorkerEnrollmentProof(context.Context, string, string, artifact.Digest) (value.WorkerEnrollmentProof, error)
}

// These identity-only ports share attestation without converting a query into
// download authority. The producing ledger validates its own parent and scope.
type AcquisitionEnrollmentBindings interface {
	ReadAcquisitionEnrollment(context.Context, value.AcquisitionParent, string) (value.AcquisitionWorkerIdentity, error)
}
type AcquisitionEnrollmentProofReader interface {
	ReadAcquisitionEnrollmentProof(context.Context, value.AcquisitionParent, string, artifact.Digest) (value.AcquisitionWorkerProof, error)
}
type WorkerCSRVerifier interface {
	EnrollmentKey([]byte) (artifact.Digest, error)
}
type WorkerEnrollmentLedger interface {
	ClaimWorkerEnrollment(context.Context, value.WorkerEnrollmentProof) (value.WorkerEnrollment, audit.Receipt, bool, error)
	PrepareWorkerCertificate(context.Context, value.WorkerEnrollmentProof) (value.WorkerCertificateProgress, error)
	StoreWorkerCertificate(context.Context, value.WorkerCertificateAttempt, value.WorkerCertificate) error
}
type WorkerCertificateActivator interface {
	ActivateWorkerCertificate(context.Context, value.WorkerEnrollmentProof, value.WorkerCertificateAttempt) (value.WorkerCertificate, error)
}
type WorkerCertificateIssuer interface {
	SignWorkerCertificate(context.Context, value.WorkerCertificateAttempt, []byte) (value.WorkerCertificate, error)
}

// WorkerEnrollmentCoordinator runs in trusted download control. The human
// credential stays at that boundary; no worker receives it or chooses authority.
type WorkerEnrollmentCoordinator struct {
	CSR              WorkerCSRVerifier
	Proofs           WorkerEnrollmentProofReader
	Ledger           WorkerEnrollmentLedger
	Activation       WorkerCertificateActivator
	Audit            auditapp.WorkerEnrollmentWriter
	Acknowledgements auditapp.WorkerEnrollmentAcknowledgements
	Issuer           WorkerCertificateIssuer
	Authority        DownloadAuthorityGate
	CurrentAuthority CurrentDownloadAuthority
	Now              func() time.Time
}

func (s *WorkerEnrollmentCoordinator) Enroll(ctx context.Context, credential, session, worker string, scope artifact.DownloadScope, csr []byte) (value.WorkerCertificate, error) {
	if s == nil || s.Authority == nil {
		return value.WorkerCertificate{}, artifact.ErrInvalid
	}
	return s.enrollChecked(ctx, session, worker, scope, csr, func(c context.Context) (artifact.DownloadAuthority, error) {
		return s.Authority.CheckDownload(c, credential, scope)
	}, nil)
}

func (s *WorkerEnrollmentCoordinator) EnrollCurrent(ctx context.Context, source identities.CurrentIdentity, session, worker string, scope artifact.DownloadScope, csr []byte) (value.WorkerCertificate, error) {
	if s == nil {
		return value.WorkerCertificate{}, artifact.ErrInvalid
	}
	check, err := newWorkerCurrentCheck(ctx, source, s.CurrentAuthority, scope, s.Now)
	if err != nil {
		return value.WorkerCertificate{}, err
	}
	call, cancel := context.WithDeadline(ctx, check.Deadline())
	defer cancel()
	return s.enrollChecked(call, session, worker, scope, csr, check.Check, check.Deadline)
}
func (s *WorkerEnrollmentCoordinator) enrollChecked(ctx context.Context, session, worker string, scope artifact.DownloadScope, csr []byte, check contextDownloadCheck, bound func() time.Time) (value.WorkerCertificate, error) {
	var zero value.WorkerCertificate
	if s == nil || ctx == nil || s.CSR == nil || s.Proofs == nil || s.Ledger == nil || s.Activation == nil || s.Audit == nil || s.Acknowledgements == nil || s.Issuer == nil || check == nil || s.Now == nil || !value.UUID(session) || !value.UUID(worker) || !scope.Valid() || len(csr) < 1 || len(csr) > 8192 {
		return zero, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	key, err := s.CSR.EnrollmentKey(csr)
	if err != nil || key == (artifact.Digest{}) {
		return zero, artifact.ErrInvalid
	}
	shorten, finish := workerEffectContext(&ctx, bound)
	defer finish()
	current := func() (value.WorkerEnrollmentProof, artifact.DownloadAuthority, error) {
		a, e := check(ctx)
		if e != nil || a.Scope != scope || !a.Valid(s.Now()) {
			return value.WorkerEnrollmentProof{}, a, artifact.ErrDownloadExpired
		}
		shorten()
		p, e := s.Proofs.ReadWorkerEnrollmentProof(ctx, session, worker, key)
		if e != nil || !p.Valid(s.Now()) || !a.Valid(s.Now()) || p.Worker.Intent.ID != worker || p.Worker.Intent.SessionID != session || p.PublicKeyDigest != key || p.Worker.Intent.Authority.Scope != scope || ctx.Err() != nil {
			return p, a, artifact.ErrDownloadExpired
		}
		final, e := check(ctx)
		if e != nil || !a.Valid(s.Now()) || !p.Valid(s.Now()) || !final.Valid(s.Now()) || final.Scope != scope || ctx.Err() != nil {
			return p, a, artifact.ErrDownloadExpired
		}
		shorten()
		return p, final, nil
	}
	return enrollAcquisition(ctx, &downloadEnrollmentFlow{service: s, check: func() (value.WorkerEnrollmentProof, error) { p, _, err := current(); return p, err }}, csr, key, s.Now)
}

// EnrollAdmitted issues identity for an already admitted worker. The caller is
// the worker's own finite HTTP request; SQL effects independently check current
// parent/configuration/recovery. The certificate confers no evidence rights.
func (s *WorkerEnrollmentCoordinator) EnrollAdmitted(ctx context.Context, session, worker string, csr []byte) (value.WorkerCertificate, error) {
	var zero value.WorkerCertificate
	if s == nil || ctx == nil || ctx.Err() != nil || s.CSR == nil || s.Proofs == nil || s.Ledger == nil || s.Activation == nil || s.Audit == nil || s.Acknowledgements == nil || s.Issuer == nil || s.Now == nil || !value.UUID(session) || !value.UUID(worker) || len(csr) < 1 || len(csr) > 8192 {
		return zero, artifact.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key, err := s.CSR.EnrollmentKey(csr)
	if err != nil || key == (artifact.Digest{}) {
		return zero, collapsed("csr", artifact.ErrInvalid, err)
	}
	p, err := s.Proofs.ReadWorkerEnrollmentProof(call, session, worker, key)
	if err != nil || !p.Valid(s.Now()) || p.Worker.Intent.SessionID != session || p.Worker.Intent.ID != worker || p.PublicKeyDigest != key || call.Err() != nil {
		return zero, collapsed("proof", artifact.ErrDownloadUnavailable, err)
	}
	proofCall, stop := context.WithDeadline(call, p.FreshUntil)
	defer stop()
	flow := &downloadEnrollmentFlow{service: s, check: func() (value.WorkerEnrollmentProof, error) {
		if proofCall.Err() != nil || !p.Valid(s.Now()) {
			return value.WorkerEnrollmentProof{}, artifact.ErrDownloadExpired
		}
		return p, nil
	}}
	return enrollAcquisition(proofCall, flow, csr, key, s.Now)
}
