package postgres

import (
	"bytes"
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	port "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EnrollmentClaimAudits struct{ claims *EnrollmentClaims }

var _ port.EnrollmentClaimLedger = (*EnrollmentClaimAudits)(nil)

func NewEnrollmentClaimAudits(ctx context.Context, pool *pgxpool.Pool, installation string) (*EnrollmentClaimAudits, error) {
	c, err := NewEnrollmentClaims(ctx, pool, installation)
	if err != nil {
		return nil, err
	}
	return &EnrollmentClaimAudits{c}, nil
}

func (a *EnrollmentClaimAudits) ReadEnrollmentClaim(ctx context.Context, installation, bootstrap string) (audit.EnrollmentClaim, error) {
	var out audit.EnrollmentClaim
	if installation != a.claims.installation || !authorization.UUID(bootstrap) {
		return out, fleet.ErrInvalid
	}
	err := a.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockFleetTrust(ctx, id(installation)); err != nil {
			return err
		}
		row, err := q.LockBootstrap(ctx, custodydb.LockBootstrapParams{InstallationID: id(installation), ID: id(bootstrap)})
		if err != nil {
			return err
		}
		out, err = enrollmentClaimAudit(row)
		return err
	})
	if err != nil {
		return audit.EnrollmentClaim{}, err
	}
	return out, nil
}

func enrollmentClaimAudit(row custodydb.FleetBootstrap) (audit.EnrollmentClaim, error) {
	r := audit.EnrollmentClaim{BootstrapID: uid(row.ID), Binding: fleet.PeerBinding{InstallationID: uid(row.InstallationID), ClusterID: uid(row.ClusterID), IssuerEpoch: uid(row.IssuerEpoch), PeerID: uid(row.PeerID), Role: fleet.ConnectorPeer}, IssueAuditID: uid(row.IssueAuditID), IssuedAt: row.NotBefore.Time.UTC(), ClaimedAt: row.ClaimedAt.Time.UTC(), NotAfter: row.NotAfter.Time.UTC()}
	copy(r.PublicKeyDigest[:], row.PublicKeySha256)
	copy(r.IssueAuthorityDigest[:], row.IssueAuthorityDigest)
	copy(r.IssueAuditDigest[:], row.IssueAuditSha256)
	if !row.ClaimedAt.Valid || !r.Valid() {
		return audit.EnrollmentClaim{}, fleet.ErrUnavailable
	}
	return r, nil
}

func (a *EnrollmentClaimAudits) PendingEnrollmentClaims(ctx context.Context) ([]audit.EnrollmentClaim, error) {
	var out []audit.EnrollmentClaim
	err := a.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.PendingEnrollmentClaims(ctx, id(a.claims.installation))
		if err != nil {
			return err
		}
		out = nil
		for _, row := range rows {
			r, err := enrollmentClaimAudit(row)
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

func (a *EnrollmentClaimAudits) AcknowledgeEnrollmentClaim(ctx context.Context, r audit.EnrollmentClaim, receipt audit.Receipt) error {
	if r.Binding.InstallationID != a.claims.installation || !r.Valid() || !receipt.ValidEnrollmentClaim(r.Binding.InstallationID, r.BootstrapID) {
		return fleet.ErrInvalid
	}
	return a.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		// Durable explanation remains possible after expiry/revocation. This
		// transaction grants no signing, registration or execution authority.
		if _, err := q.LockFleetTrust(ctx, id(r.Binding.InstallationID)); err != nil {
			return err
		}
		row, err := q.LockBootstrap(ctx, custodydb.LockBootstrapParams{InstallationID: id(r.Binding.InstallationID), ID: id(r.BootstrapID)})
		if err != nil {
			return err
		}
		frozen, err := enrollmentClaimAudit(row)
		if err != nil {
			return err
		}
		if !bytes.Equal(digest(frozen), digest(r)) {
			return fleet.ErrDenied
		}
		if row.ClaimAcknowledgedAt.Valid {
			if !bytes.Equal(row.ClaimAuditDigest, digest(r)) || row.ClaimObjectKey.String != receipt.Key || row.ClaimObjectVersion.String != receipt.Version || row.ClaimObjectEtag.String != receipt.ETag || row.ClaimObjectBytes.Int64 != receipt.Bytes || !bytes.Equal(row.ClaimObjectSha256, receipt.SHA256[:]) {
				return fleet.ErrDenied
			}
			return nil
		}
		n, err := q.AcknowledgeEnrollmentClaim(ctx, custodydb.AcknowledgeEnrollmentClaimParams{InstallationID: row.InstallationID, ID: row.ID, ClaimAuditDigest: digest(r), ClaimObjectKey: pgtype.Text{String: receipt.Key, Valid: true}, ClaimObjectVersion: pgtype.Text{String: receipt.Version, Valid: true}, ClaimObjectEtag: pgtype.Text{String: receipt.ETag, Valid: true}, ClaimObjectBytes: pgtype.Int8{Int64: receipt.Bytes, Valid: true}, ClaimObjectSha256: receipt.SHA256[:]})
		if err != nil {
			return err
		}
		if n != 1 {
			return fleet.ErrDenied
		}
		return nil
	})
}
