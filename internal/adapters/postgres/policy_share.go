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
	if row.SharingStoppedAt.Valid {
		out.StoppedAt = row.SharingStoppedAt.Time.UTC()
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

// policySharingRevision is the sharing's revision: 1, plus one for a Stop and
// one for a revocation.
func policySharingRevision(row custodydb.PolicyAcceptance) int64 {
	n := int64(1)
	if row.SharingStoppedAt.Valid {
		n++
	}
	if row.SharingRevokedAt.Valid {
		n++
	}
	return n
}

// RevokePolicySharing marks the acceptance's sharing revoked and revokes
// every still-unrevoked share it materialized, in one transaction under the
// current recovery fence. The acceptance row lock orders it before any later
// slot claim (admission) and against publication, which then materializes
// nothing. The same key after success is a replay; another key or a stale
// expected revision is Conflict.
func (s *EvidenceShares) RevokePolicySharing(ctx context.Context, r sharing.PolicyRevocation, recovery artifact.RecoveryProof) (int, bool, error) {
	var revoked int
	replay, err := s.changePolicySharing(ctx, r, recovery, func(q *custodydb.Queries, row custodydb.PolicyAcceptance, key pgtype.Text) (bool, error) {
		revoked = 0
		if row.SharingRevokedAt.Valid {
			if row.SharingRevokeKey != key {
				return false, value.ErrConflict
			}
			n, err := q.CountPolicyShareRevocations(ctx, custodydb.CountPolicyShareRevocationsParams{RootID: id(s.root), PolicyAcceptanceID: row.ID, RevokeKey: key})
			revoked = int(n)
			return true, err
		}
		if r.ExpectedRevision != policySharingRevision(row) {
			return false, value.ErrConflict
		}
		n, err := q.RevokePolicySharing(ctx, custodydb.RevokePolicySharingParams{RootID: id(s.root), ID: row.ID, SharingRevokeKey: key})
		if err != nil {
			return false, err
		}
		if n != 1 {
			return false, value.ErrConflict
		}
		ids, err := q.RevokePolicyShares(ctx, custodydb.RevokePolicySharesParams{RootID: id(s.root), PolicyAcceptanceID: row.ID, RevokeKey: key})
		revoked = len(ids)
		return false, err
	})
	if err != nil {
		return 0, false, err
	}
	return revoked, replay, nil
}

// StopPolicySharing stops future sharing (REQ-SHR-007): no further capture
// claims a slot, while captures that already claimed one still publish their
// shares before notAfter, and existing shares stay until they expire or are
// revoked. Expected must be revision 1; the same key after success is a
// replay; a stopped or revoked sharing otherwise is Conflict.
func (s *EvidenceShares) StopPolicySharing(ctx context.Context, r sharing.PolicyRevocation, recovery artifact.RecoveryProof) (bool, error) {
	return s.changePolicySharing(ctx, r, recovery, func(q *custodydb.Queries, row custodydb.PolicyAcceptance, key pgtype.Text) (bool, error) {
		if row.SharingStoppedAt.Valid && row.SharingStopKey == key {
			return true, nil
		}
		if row.SharingStoppedAt.Valid || row.SharingRevokedAt.Valid || r.ExpectedRevision != 1 {
			return false, value.ErrConflict
		}
		n, err := q.StopPolicySharing(ctx, custodydb.StopPolicySharingParams{RootID: id(s.root), ID: row.ID, SharingStopKey: key})
		if err == nil && n != 1 {
			err = value.ErrConflict
		}
		return false, err
	})
}

// changePolicySharing locks the acceptance under the current recovery fence,
// authorizes the actor (creator, a pinned current manager the service found,
// or an administrator) and applies change.
func (s *EvidenceShares) changePolicySharing(ctx context.Context, r sharing.PolicyRevocation, recovery artifact.RecoveryProof, change func(*custodydb.Queries, custodydb.PolicyAcceptance, pgtype.Text) (bool, error)) (bool, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(r.AcceptanceID) || !r.Actor.Valid() || len(r.Managers) > authorization.ShareMaxManagers || !identity.Text(r.IdempotencyKey, 128) || r.ExpectedRevision < 1 {
		return false, value.ErrInvalid
	}
	replay := false
	key := pgtype.Text{String: r.IdempotencyKey, Valid: true}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
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
		if replay, err = change(q, row, key); err != nil {
			return err
		}
		if err = s.recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return false, shareError(err)
	}
	return replay, nil
}
