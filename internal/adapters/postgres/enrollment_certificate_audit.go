package postgres

import (
	"bytes"
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	port "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EnrollmentCertificateAudits struct{ claims *EnrollmentClaims }

var _ port.EnrollmentCertificateLedger = (*EnrollmentCertificateAudits)(nil)

func NewEnrollmentCertificateAudits(ctx context.Context, pool *pgxpool.Pool, installation string) (*EnrollmentCertificateAudits, error) {
	c, err := NewEnrollmentClaims(ctx, pool, installation)
	if err != nil {
		return nil, err
	}
	return &EnrollmentCertificateAudits{c}, nil
}
func certificateAudit(row custodydb.FleetCertificateIssue, slot custodydb.FleetBootstrap) (audit.EnrollmentCertificate, error) {
	var out audit.EnrollmentCertificate
	a, err := signingAttempt(row, slot)
	if err != nil {
		return out, err
	}
	c, err := issuedCertificate(row, a)
	if err != nil {
		return out, err
	}
	out = audit.EnrollmentCertificate{Attempt: a, Certificate: c.Certificate}
	if !out.Valid() {
		return audit.EnrollmentCertificate{}, fleet.ErrUnavailable
	}
	return out, nil
}
func (a *EnrollmentCertificateAudits) PendingEnrollmentCertificates(ctx context.Context) ([]audit.EnrollmentCertificate, error) {
	var out []audit.EnrollmentCertificate
	err := a.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = nil
		if _, err := q.LockFleetTrust(ctx, id(a.claims.installation)); err != nil {
			return err
		}
		rows, err := q.PendingEnrollmentCertificates(ctx, id(a.claims.installation))
		if err != nil {
			return err
		}
		for _, row := range rows {
			slot, err := q.LockBootstrap(ctx, custodydb.LockBootstrapParams{InstallationID: row.InstallationID, ID: row.BootstrapID})
			if err != nil {
				return err
			}
			r, err := certificateAudit(row, slot)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (a *EnrollmentCertificateAudits) AcknowledgeEnrollmentCertificate(ctx context.Context, r audit.EnrollmentCertificate, receipt audit.Receipt) error {
	installation := r.Certificate.Binding.InstallationID
	if installation != a.claims.installation || !r.Valid() || !receipt.ValidEnrollmentCertificate(installation, r.Attempt.ID) {
		return fleet.ErrInvalid
	}
	return a.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockFleetTrust(ctx, id(installation)); err != nil {
			return err
		}
		slot, err := q.LockBootstrap(ctx, custodydb.LockBootstrapParams{InstallationID: id(installation), ID: id(r.Attempt.Permit.Enrollment.BootstrapID)})
		if err != nil {
			return err
		}
		rows, err := q.ReadCertificateIssues(ctx, custodydb.ReadCertificateIssuesParams{InstallationID: slot.InstallationID, BootstrapID: slot.ID})
		if err != nil {
			return err
		}
		for _, row := range rows {
			if uid(row.ID) != r.Attempt.ID {
				continue
			}
			frozen, err := certificateAudit(row, slot)
			if err != nil {
				return err
			}
			if !bytes.Equal(digest(frozen), digest(r)) {
				return fleet.ErrDenied
			}
			if row.AuditAcknowledgedAt.Valid {
				if !bytes.Equal(row.AuditDigest, digest(r)) || row.AuditObjectKey.String != receipt.Key || row.AuditObjectVersion.String != receipt.Version || row.AuditObjectEtag.String != receipt.ETag || row.AuditObjectBytes.Int64 != receipt.Bytes || !bytes.Equal(row.AuditObjectSha256, receipt.SHA256[:]) {
					return fleet.ErrDenied
				}
				return nil
			}
			n, err := q.AcknowledgeEnrollmentCertificate(ctx, custodydb.AcknowledgeEnrollmentCertificateParams{InstallationID: row.InstallationID, ID: row.ID, AuditDigest: digest(r), AuditObjectKey: pgtype.Text{String: receipt.Key, Valid: true}, AuditObjectVersion: pgtype.Text{String: receipt.Version, Valid: true}, AuditObjectEtag: pgtype.Text{String: receipt.ETag, Valid: true}, AuditObjectBytes: pgtype.Int8{Int64: receipt.Bytes, Valid: true}, AuditObjectSha256: receipt.SHA256[:]})
			if err != nil {
				return err
			}
			if n != 1 {
				return fleet.ErrDenied
			}
			return nil
		}
		return fleet.ErrDenied
	})
}
