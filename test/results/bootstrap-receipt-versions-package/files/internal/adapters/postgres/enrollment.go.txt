package postgres

import (
	"context"
	"crypto/subtle"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	port "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EnrollmentClaims struct {
	ledger       *Ledger
	installation string
}

var _ port.EnrollmentLedger = (*EnrollmentClaims)(nil)

func NewEnrollmentClaims(ctx context.Context, pool *pgxpool.Pool, installation string) (*EnrollmentClaims, error) {
	if !authorization.UUID(installation) {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var version int64
	if err = pool.QueryRow(ctx, "SELECT version_id FROM goose_db_version ORDER BY id DESC LIMIT 1").Scan(&version); err != nil || version != currentSchemaVersion {
		return nil, value.ErrUnavailable
	}
	return &EnrollmentClaims{ledger: l, installation: installation}, nil
}

func (p *EnrollmentClaims) ClaimConnector(ctx context.Context, c value.EnrollmentClaim) (value.Enrollment, error) {
	var out value.Enrollment
	if !c.Valid() || c.InstallationID != p.installation {
		return out, value.ErrInvalid
	}
	err := p.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = value.Enrollment{}
		root, e := q.LockFleetTrust(ctx, id(c.InstallationID))
		if e != nil {
			return value.ErrDenied
		}
		slot, e := q.LockBootstrap(ctx, custodydb.LockBootstrapParams{InstallationID: id(c.InstallationID), ID: id(c.BootstrapID)})
		if e != nil {
			return value.ErrDenied
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return value.ErrUnavailable
		}
		revision := identity.Revision{UID: root.SourceUid, Generation: root.SourceGeneration}
		copy(revision.Digest[:], root.SourceDigest)
		if !currentIssuedBootstrapAudit(slot) || root.Suspended || root.RecoveryBlocked || !revision.Valid() || !identity.Fresh(root.ObservedAt.Time, root.FreshUntil.Time, now.Time, 30*time.Second) || slot.IssuerEpoch != root.IssuerEpoch || slot.Revoked || now.Time.Before(slot.NotBefore.Time) || !now.Time.Before(slot.NotAfter.Time) || subtle.ConstantTimeCompare(slot.SecretSha256, c.SecretDigest[:]) != 1 {
			return value.ErrDenied
		}
		out = value.Enrollment{BootstrapID: c.BootstrapID, Binding: value.PeerBinding{InstallationID: c.InstallationID, ClusterID: uid(slot.ClusterID), IssuerEpoch: uid(slot.IssuerEpoch), PeerID: uid(slot.PeerID), Role: value.ConnectorPeer}, PublicKeyDigest: c.PublicKeyDigest, NotAfter: slot.NotAfter.Time.UTC(), Replay: slot.ClaimedAt.Valid}
		if !out.Binding.Valid() {
			return value.ErrDenied
		}
		if slot.ClaimedAt.Valid {
			if subtle.ConstantTimeCompare(slot.PublicKeySha256, c.PublicKeyDigest[:]) != 1 {
				return value.ErrDenied
			}
		} else {
			slot, e = q.ClaimBootstrap(ctx, custodydb.ClaimBootstrapParams{InstallationID: id(c.InstallationID), ID: id(c.BootstrapID), PublicKeySha256: c.PublicKeyDigest[:]})
			if e != nil {
				return value.ErrUnavailable
			}
		}
		out.ClaimedAt = slot.ClaimedAt.Time.UTC()
		// Recheck after the write as well as after blocking row locks. Expiry
		// rolls back this uncommitted claim; an unknown COMMIT is never refunded.
		now, e = q.CurrentTime(ctx)
		if e != nil {
			return value.ErrUnavailable
		}
		if !now.Time.Before(slot.NotAfter.Time) || !now.Time.Before(root.FreshUntil.Time) || now.Time.Before(out.ClaimedAt) {
			return value.ErrDenied
		}
		return nil
	})
	if err != nil {
		return value.Enrollment{}, err
	}
	return out, nil
}
