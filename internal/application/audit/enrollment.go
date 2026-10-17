package audit

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/audit"
)

type EnrollmentClaimLedger interface {
	ReadEnrollmentClaim(context.Context, string, string) (value.EnrollmentClaim, error)
	PendingEnrollmentClaims(context.Context) ([]value.EnrollmentClaim, error)
	AcknowledgeEnrollmentClaim(context.Context, value.EnrollmentClaim, value.Receipt) error
}
type EnrollmentClaimWriter interface {
	WriteEnrollmentClaim(context.Context, value.EnrollmentClaim) (value.Receipt, error)
}

type EnrollmentCertificateLedger interface {
	PendingEnrollmentCertificates(context.Context) ([]value.EnrollmentCertificate, error)
	AcknowledgeEnrollmentCertificate(context.Context, value.EnrollmentCertificate, value.Receipt) error
}
type EnrollmentCertificateWriter interface {
	WriteEnrollmentCertificate(context.Context, value.EnrollmentCertificate) (value.Receipt, error)
}

type EnrollmentCertificatePublisher struct {
	Ledger  EnrollmentCertificateLedger
	Objects EnrollmentCertificateWriter
}

func (p EnrollmentCertificatePublisher) PublishEnrollmentCertificates(ctx context.Context) error {
	if p.Ledger == nil || p.Objects == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := p.Ledger.PendingEnrollmentCertificates(ctx)
	if err != nil {
		return err
	}
	if len(rows) > 2 {
		return ErrUnavailable
	}
	for _, r := range rows {
		if !r.Valid() || ctx.Err() != nil {
			return ErrUnavailable
		}
		receipt, err := p.Objects.WriteEnrollmentCertificate(ctx, r)
		if err != nil {
			return err
		}
		if !receipt.ValidEnrollmentCertificate(r.Certificate.Binding.InstallationID, r.Attempt.ID) {
			return ErrUnavailable
		}
		if err = p.Ledger.AcknowledgeEnrollmentCertificate(ctx, r, receipt); err != nil {
			return err
		}
	}
	return nil
}

type EnrollmentClaimPublisher struct {
	Ledger  EnrollmentClaimLedger
	Objects EnrollmentClaimWriter
}

func (p EnrollmentClaimPublisher) PublishEnrollmentClaims(ctx context.Context) error {
	if p.Ledger == nil || p.Objects == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := p.Ledger.PendingEnrollmentClaims(ctx)
	if err != nil {
		return err
	}
	if len(rows) > 2 {
		return ErrUnavailable
	}
	for _, r := range rows {
		if !r.Valid() || ctx.Err() != nil {
			return ErrUnavailable
		}
		receipt, err := p.Objects.WriteEnrollmentClaim(ctx, r)
		if err != nil {
			return err
		}
		if !receipt.ValidEnrollmentClaim(r.Binding.InstallationID, r.BootstrapID) {
			return ErrUnavailable
		}
		if err = p.Ledger.AcknowledgeEnrollmentClaim(ctx, r, receipt); err != nil {
			return err
		}
	}
	return nil
}
