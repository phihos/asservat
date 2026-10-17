package evidence

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"crypto/sha256"
	"time"
)

type WorkerEnrollmentBindings interface {
	ReadDownloadWorkerEnrollment(context.Context, string, string) (value.DownloadWorkerIdentity, error)
}
type WorkerEnrollmentProofReader interface {
	ReadWorkerEnrollmentProof(context.Context, string, string, artifact.Digest) (value.WorkerEnrollmentProof, error)
}
type WorkerCSRVerifier interface {
	EnrollmentKey([]byte) (artifact.Digest, error)
}
type WorkerEnrollmentLedger interface {
	ClaimWorkerEnrollment(context.Context, value.WorkerEnrollmentProof, artifact.DownloadAuthority) (value.WorkerEnrollment, audit.Receipt, bool, error)
	PrepareWorkerCertificate(context.Context, value.WorkerEnrollmentProof, artifact.DownloadAuthority) (value.WorkerCertificateProgress, error)
	StoreWorkerCertificate(context.Context, value.WorkerCertificateAttempt, value.WorkerCertificate, artifact.DownloadAuthority) error
}
type WorkerCertificateActivator interface {
	ActivateWorkerCertificate(context.Context, value.WorkerEnrollmentProof, value.WorkerCertificateAttempt, artifact.DownloadAuthority) (value.WorkerCertificate, error)
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
	p, a, err := current()
	if err != nil {
		return zero, err
	}
	e, receipt, acknowledged, err := s.Ledger.ClaimWorkerEnrollment(ctx, p, a)
	if err != nil {
		return zero, err
	}
	if !e.Valid() || e.Worker != p.Worker || e.PublicKeyDigest != key {
		return zero, artifact.ErrIntegrity
	}
	if !acknowledged {
		p, a, err = current()
		if err != nil {
			return zero, err
		}
		receipt, err = s.Audit.WriteWorkerEnrollment(ctx, e)
		if err != nil {
			return zero, err
		}
		if !receipt.ValidWorkerEnrollment(e) {
			return zero, artifact.ErrIntegrity
		}
		p, a, err = current()
		if err != nil {
			return zero, err
		}
		if err = s.Acknowledgements.AcknowledgeWorkerEnrollment(ctx, e, receipt); err != nil {
			return zero, err
		}
	} else if !receipt.ValidWorkerEnrollment(e) {
		return zero, artifact.ErrIntegrity
	}
	p, a, err = current()
	if err != nil {
		return zero, err
	}
	progress, err := s.Ledger.PrepareWorkerCertificate(ctx, p, a)
	if err != nil {
		return zero, err
	}
	attempt := progress.Attempt
	if attempt.Enrollment != e || !attempt.Valid(attempt.CheckedAt) {
		return zero, artifact.ErrIntegrity
	}
	p, a, err = current()
	if err != nil {
		return zero, err
	}
	if progress.MaySign {
		if progress.Signed != nil || !attempt.Valid(s.Now()) {
			return zero, artifact.ErrDownloadExpired
		}
		signing, cancel := context.WithDeadline(ctx, attempt.SignBefore)
		c, err := s.Issuer.SignWorkerCertificate(signing, attempt, csr)
		cancel()
		if err != nil {
			return zero, err
		}
		if !attempt.Valid(s.Now()) || !attempt.Matches(c) || artifact.Digest(sha256.Sum256(c.DER)) != c.Peer.Certificate {
			return zero, artifact.ErrIntegrity
		}
		p, a, err = current()
		if err != nil {
			return zero, err
		}
		if err = s.Ledger.StoreWorkerCertificate(ctx, attempt, c, a); err != nil {
			return zero, err
		}
		progress.Signed = &c
	}
	if progress.Signed == nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	if !attempt.Matches(*progress.Signed) || artifact.Digest(sha256.Sum256(progress.Signed.DER)) != progress.Signed.Peer.Certificate {
		return zero, artifact.ErrIntegrity
	}
	record := audit.WorkerCertificate{Attempt: attempt, Peer: progress.Signed.Peer}
	r, ok, err := s.Acknowledgements.ReadWorkerCertificateReceipt(ctx, record)
	if err != nil {
		return zero, err
	}
	if !ok {
		p, a, err = current()
		if err != nil {
			return zero, err
		}
		r, err = s.Audit.WriteWorkerCertificate(ctx, record)
		if err != nil {
			return zero, err
		}
		if !r.ValidWorkerCertificate(record) {
			return zero, artifact.ErrIntegrity
		}
		p, a, err = current()
		if err != nil {
			return zero, err
		}
		if err = s.Acknowledgements.AcknowledgeWorkerCertificate(ctx, record, r); err != nil {
			return zero, err
		}
	} else if !r.ValidWorkerCertificate(record) {
		return zero, artifact.ErrIntegrity
	}
	p, a, err = current()
	if err != nil {
		return zero, err
	}
	c, err := s.Activation.ActivateWorkerCertificate(ctx, p, attempt, a)
	if err != nil {
		return zero, err
	}
	if !attempt.Matches(c) || c.Peer != progress.Signed.Peer || artifact.Digest(sha256.Sum256(c.DER)) != c.Peer.Certificate || !p.Valid(s.Now()) || !a.Valid(s.Now()) || !c.Peer.Valid(s.Now()) || ctx.Err() != nil {
		return zero, artifact.ErrIntegrity
	}
	if _, _, err = current(); err != nil {
		return zero, err
	}
	return c, nil
}
