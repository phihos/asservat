package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ADR-239: recurring policy sharing (migration 00092). The acceptance record
// carries the immutable instruction; the admission and publication triggers
// spend and materialize it. This ledger only reads it and revokes it.

var _ sharing.PolicySharingStore = (*EvidenceShares)(nil)

func policySharingFrom(row custodydb.PolicyAcceptance) (sharing.PolicySharing, error) {
	record, err := decodePolicy(row)
	if err != nil || record.Sharing == nil {
		return sharing.PolicySharing{}, value.ErrUnavailable
	}
	out := sharing.PolicySharing{AcceptanceID: record.ID, Instruction: *record.Sharing, Target: authorization.PolicyScope(record.Authority)}
	if row.SharingRevokedAt.Valid {
		out.RevokedAt = row.SharingRevokedAt.Time.UTC()
	}
	return out, nil
}

// PolicySharing reads one acceptance's sharing instruction. An acceptance
// without sharing (or none) is Denied without saying which.
func (s *EvidenceShares) PolicySharing(ctx context.Context, acceptanceID string) (sharing.PolicySharing, error) {
	var zero sharing.PolicySharing
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(acceptanceID) {
		return zero, value.ErrUnavailable
	}
	row, err := custodydb.New(s.ledger.pool).ReadPolicySharingAcceptance(ctx, custodydb.ReadPolicySharingAcceptanceParams{RootID: id(s.root), ID: id(acceptanceID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, value.ErrDenied
	}
	if err != nil {
		return zero, value.ErrUnavailable
	}
	return policySharingFrom(row)
}

// RevokePolicySharing marks the acceptance's sharing revoked and revokes
// every still-unrevoked share it materialized, in one transaction under the
// current recovery fence. The acceptance row lock orders it before any later
// slot claim (admission) and against publication, which then materializes
// nothing. The same key after success is a replay; another key or a stale
// expected revision is Conflict.
func (s *EvidenceShares) RevokePolicySharing(ctx context.Context, r sharing.PolicyRevocation, recovery artifact.RecoveryProof) (int, bool, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(r.AcceptanceID) || !r.Actor.Valid() || len(r.Managers) > authorization.ShareMaxManagers || !identity.Text(r.IdempotencyKey, 128) || r.ExpectedRevision < 1 {
		return 0, false, value.ErrInvalid
	}
	var revoked int
	replay := false
	key := pgtype.Text{String: r.IdempotencyKey, Valid: true}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		revoked, replay = 0, false
		trust, err := s.recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		row, err := q.LockPolicySharingAcceptance(ctx, custodydb.LockPolicySharingAcceptanceParams{RootID: id(s.root), ID: id(r.AcceptanceID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return value.ErrDenied
		}
		if err != nil {
			return err
		}
		current, err := policySharingFrom(row)
		if err != nil {
			return err
		}
		management, err := json.Marshal(current.Instruction.Management)
		if err != nil {
			return value.ErrUnavailable
		}
		creator := current.Instruction.Creator
		if !r.Administrator && (creator.Issuer != r.Actor.Issuer || creator.Subject != r.Actor.Subject) && !pinsAll(management, r.Managers) {
			return value.ErrDenied
		}
		switch {
		case row.SharingRevokedAt.Valid && row.SharingRevokeKey == key:
			replay = true
			n, err := q.CountPolicyShareRevocations(ctx, custodydb.CountPolicyShareRevocationsParams{RootID: id(s.root), PolicyAcceptanceID: row.ID, RevokeKey: key})
			if err != nil {
				return err
			}
			revoked = int(n)
		case row.SharingRevokedAt.Valid || r.ExpectedRevision != 1:
			return value.ErrConflict
		default:
			n, err := q.RevokePolicySharing(ctx, custodydb.RevokePolicySharingParams{RootID: id(s.root), ID: row.ID, SharingRevokeKey: key})
			if err != nil {
				return err
			}
			if n != 1 {
				return value.ErrConflict
			}
			ids, err := q.RevokePolicyShares(ctx, custodydb.RevokePolicySharesParams{RootID: id(s.root), PolicyAcceptanceID: row.ID, RevokeKey: key})
			if err != nil {
				return err
			}
			revoked = len(ids)
		}
		if err = s.recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return 0, false, shareError(err)
	}
	return revoked, replay, nil
}
