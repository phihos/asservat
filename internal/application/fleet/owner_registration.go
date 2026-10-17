package fleet

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"bytes"
	"context"
	"crypto/sha256"
	"time"
)

type OwnerEnrollmentLedger interface {
	ClaimOwnerEnrollment(context.Context, value.OwnerEnrollmentProof) (value.OwnerEnrollment, audit.Receipt, bool, error)
	PrepareOwnerCertificate(context.Context, value.OwnerEnrollmentProof) (value.OwnerCertificateProgress, error)
	StoreOwnerCertificate(context.Context, value.OwnerCertificateAttempt, value.IssuedOwnerCertificate) error
}
type OwnerCertificateActivator interface {
	ActivateOwnerCertificate(context.Context, value.OwnerEnrollmentProof, value.OwnerCertificateAttempt) (value.IssuedOwnerCertificate, error)
}
type OwnerCertificateRegistry interface {
	ReadOwnerRegistration(context.Context, value.OwnerCertificate) (value.OwnerRegistrationObservation, error)
}
type OwnerEnrollmentCleanup interface {
	RetireOwnerEnrollment(context.Context, value.OwnerEnrollment) error
	PruneOwnerEnrollments(context.Context) error
}
type OwnerEnrollmentVerifier interface {
	EnrollmentKey([]byte) (artifact.Digest, error)
	CheckOwnerCertificateCurrent(value.OwnerCertificatePermit, []byte, []byte, [][]byte, value.OwnerConfigurationObservation) (value.IssuedOwnerCertificate, error)
}

// Trusted private composition only. A Pod proof is not a user-selected signing
// permit. Auditors and activators use independently limited SQL credentials.
type OwnerEnrollmentCoordinator struct {
	Verifier         OwnerEnrollmentVerifier
	Proofs           OwnerEnrollmentProofReader
	Ledger           OwnerEnrollmentLedger
	Activation       OwnerCertificateActivator
	Audit            auditapp.OwnerEnrollmentWriter
	Acknowledgements auditapp.OwnerEnrollmentAcknowledgements
	Issuer           OwnerCertificateIssuer
	Now              func() time.Time
}

func (s *OwnerEnrollmentCoordinator) Enroll(ctx context.Context, request value.OwnerEnrollmentRequest) (value.IssuedOwnerCertificate, error) {
	var zero value.IssuedOwnerCertificate
	if s == nil || ctx == nil || s.Verifier == nil || s.Proofs == nil || s.Ledger == nil || s.Activation == nil || s.Audit == nil || s.Acknowledgements == nil || s.Issuer == nil || s.Now == nil || !request.Valid() {
		return zero, value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	request.CSRDER = bytes.Clone(request.CSRDER)
	key, err := s.Verifier.EnrollmentKey(request.CSRDER)
	if err != nil || key == (artifact.Digest{}) {
		return zero, value.ErrDenied
	}
	current := func() (value.OwnerEnrollmentProof, error) {
		p, e := s.Proofs.ReadOwnerEnrollmentProof(ctx, request)
		if e != nil || !p.Valid(s.Now()) || p.Binding != request.Binding || p.Usage != request.Usage || p.PublicKeyDigest != key || ctx.Err() != nil {
			return value.OwnerEnrollmentProof{}, value.ErrUnavailable
		}
		return p.Clone(), nil
	}
	p, err := current()
	if err != nil {
		return zero, err
	}
	enrollment, r, ack, err := s.Ledger.ClaimOwnerEnrollment(ctx, p)
	if err != nil {
		return zero, err
	}
	if !enrollment.Matches(p) {
		return zero, value.ErrDenied
	}
	if !ack {
		r, err = s.Audit.WriteOwnerEnrollment(ctx, enrollment)
		if err != nil {
			return zero, err
		}
		if !r.ValidOwnerEnrollment(enrollment) {
			return zero, value.ErrDenied
		}
		if err = s.Acknowledgements.AcknowledgeOwnerEnrollment(ctx, enrollment, r); err != nil {
			return zero, err
		}
	} else if !r.ValidOwnerEnrollment(enrollment) {
		return zero, value.ErrDenied
	}
	p, err = current()
	if err != nil {
		return zero, err
	}
	progress, err := s.Ledger.PrepareOwnerCertificate(ctx, p)
	if err != nil {
		return zero, err
	}
	a := progress.Attempt.Clone()
	if a.Enrollment != enrollment || !a.Valid(a.Permit.CheckedAt) || a.Permit.EnrollmentAudit != r.SHA256 {
		return zero, value.ErrDenied
	}
	if progress.MaySign {
		if progress.Signed != nil || !a.Valid(s.Now()) {
			return zero, value.ErrUnavailable
		}
		signing, cancel := context.WithDeadline(ctx, a.Permit.SignBefore)
		c, e := s.Issuer.SignOwnerCertificate(signing, a.Permit, request.CSRDER)
		cancel()
		if e != nil {
			return zero, e
		}
		if !a.Valid(s.Now()) {
			return zero, value.ErrUnavailable
		}
		checked, e := s.Verifier.CheckOwnerCertificateCurrent(a.Permit, request.CSRDER, c.DER, c.ChainDER, p.Configuration)
		if e != nil || checked.Certificate != c.Certificate {
			return zero, value.ErrDenied
		}
		if err = s.Ledger.StoreOwnerCertificate(ctx, a, checked); err != nil {
			return zero, err
		}
		progress.Signed = &checked
	}
	if progress.Signed == nil {
		return zero, value.ErrUnavailable
	}
	c := progress.Signed.Clone()
	if !a.Permit.Matches(c) || artifact.Digest(sha256.Sum256(c.DER)) != c.Certificate.Digest {
		return zero, value.ErrDenied
	}
	record := audit.OwnerCertificate{Attempt: a, Certificate: c.Certificate}
	receipt, ok, err := s.Acknowledgements.ReadOwnerCertificateReceipt(ctx, record)
	if err != nil {
		return zero, err
	}
	if !ok {
		receipt, err = s.Audit.WriteOwnerCertificate(ctx, record)
		if err != nil {
			return zero, err
		}
		if !receipt.ValidOwnerCertificate(record) {
			return zero, value.ErrDenied
		}
		if err = s.Acknowledgements.AcknowledgeOwnerCertificate(ctx, record, receipt); err != nil {
			return zero, err
		}
	} else if !receipt.ValidOwnerCertificate(record) {
		return zero, value.ErrDenied
	}
	p, err = current()
	if err != nil {
		return zero, err
	}
	checked, err := s.Verifier.CheckOwnerCertificateCurrent(a.Permit, request.CSRDER, c.DER, c.ChainDER, p.Configuration)
	if err != nil || checked.Certificate != c.Certificate {
		return zero, value.ErrDenied
	}
	activated, err := s.Activation.ActivateOwnerCertificate(ctx, p, a)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(activated.DER, checked.DER) || activated.Certificate != checked.Certificate || !p.Valid(s.Now()) || !activated.Certificate.Valid(s.Now()) || ctx.Err() != nil {
		return zero, value.ErrDenied
	}
	return checked.Clone(), nil
}
