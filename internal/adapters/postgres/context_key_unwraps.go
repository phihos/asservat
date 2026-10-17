package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContextKeyUnwrapAllowance is three keyset roles times four verification
// attempts of one stored artifact (ADR-181).
const ContextKeyUnwrapAllowance = 12

// ContextKeyUnwraps authorizes the publication verifier's artifact keyset
// unwraps (ADR-181). The authority ID is the attempt of a stored API context
// execution whose capture is not yet published. Each unwrap spends one of a
// bounded, never refunded allowance; a published capture gets none.
type ContextKeyUnwraps struct {
	ledger   *Ledger
	root     string
	epoch    string
	scope    authorization.KeyScope
	recovery *RecoveryReader
	guard    *RecoveryTransactionGuard
}

var _ authapp.KeyOperationAuthorizer = (*ContextKeyUnwraps)(nil)

func NewContextKeyUnwraps(ctx context.Context, pool *pgxpool.Pool, root, epoch string, scope authorization.KeyScope) (*ContextKeyUnwraps, error) {
	if !authorization.UUID(root) || !authorization.UUID(epoch) || !scope.Valid() || scope.Purpose != "artifact" {
		return nil, authapp.ErrKeyUnavailable
	}
	ledger, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	recovery, err := NewRecoveryReader(ctx, pool, scope.InstallationID)
	if err != nil {
		return nil, err
	}
	guard, err := NewRecoveryTransactionGuard(root, scope.InstallationID)
	if err != nil {
		return nil, err
	}
	return &ContextKeyUnwraps{ledger: ledger, root: root, epoch: epoch, scope: scope, recovery: recovery, guard: guard}, nil
}

func (s *ContextKeyUnwraps) Resolve(ctx context.Context, peer authorization.KeyPeer, r authorization.KeyRequestInfo) (authorization.KeyOperationPermit, error) {
	var out authorization.KeyOperationPermit
	if s == nil || ctx == nil || ctx.Err() != nil || r.Scope != s.scope || r.Operation != "unwrap" || !authorization.UUID(r.AuthorityID) || r.RequestDigest == (artifact.Digest{}) || len(r.Binding) < 1 || len(r.Binding) > 2048 || peer.Role != "verifier" || !peer.CanRequest(s.scope, "unwrap") {
		return out, authapp.ErrKeyDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	proof, err := s.recovery.RecoveryState(ctx)
	if err != nil || proof.InstallationID != s.scope.InstallationID {
		return out, authapp.ErrKeyDenied
	}
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, err := s.guard.lock(ctx, q, s.root, proof)
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil || !peer.Valid(now.Time) {
			return authapp.ErrKeyDenied
		}
		exec, err := q.ShareContextKeyUnwrapExecution(ctx, custodydb.ShareContextKeyUnwrapExecutionParams{AttemptID: id(r.AuthorityID), RootID: id(s.root)})
		if err != nil || exec.Phase != "stored" || exec.Published || len(exec.ExpectationDigest) != 32 {
			return authapp.ErrKeyDenied
		}
		var e artifact.ContextExpectation
		if json.Unmarshal(exec.ExpectationJson, &e) != nil || e.Validate() != nil || e.Registration.Location.AttemptID != r.AuthorityID {
			return authapp.ErrKeyDenied
		}
		digest := evidence.ContextExpectationDigest(e)
		if !bytes.Equal(digest[:], exec.ExpectationDigest) {
			return authapp.ErrKeyDenied
		}
		known := false
		for _, role := range contextKeyRoles {
			binding, err := evidence.ArtifactKeyBinding(e.Binding(), role)
			if err != nil {
				return err
			}
			known = known || bytes.Equal(binding, r.Binding)
		}
		if !known {
			return authapp.ErrKeyDenied
		}
		_, err = q.LockContextKeyUnwrap(ctx, custodydb.LockContextKeyUnwrapParams{AttemptID: id(r.AuthorityID), RootID: id(s.root)})
		var affected int64
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			affected, err = q.InsertContextKeyUnwrap(ctx, custodydb.InsertContextKeyUnwrapParams{AttemptID: id(r.AuthorityID), RootID: id(s.root), LastCertificateSha256: peer.Certificate[:]})
		case err != nil:
			return err
		default:
			affected, err = q.SpendContextKeyUnwrap(ctx, custodydb.SpendContextKeyUnwrapParams{AttemptID: id(r.AuthorityID), RootID: id(s.root), LastCertificateSha256: peer.Certificate[:]})
		}
		if err != nil || affected != 1 {
			return authapp.ErrKeyDenied
		}
		if err = s.guard.check(ctx, q, trust, s.root, proof); err != nil {
			return err
		}
		end := identity.Earlier(peer.NotAfter, identity.Earlier(start.Add(5*time.Second), proof.FreshUntil))
		out = authorization.KeyOperationPermit{AuthorityID: r.AuthorityID, RecoveryEpoch: s.epoch, Revision: uint64(max(proof.Revision.Generation, 1)), Certificate: peer.Certificate, RequestDigest: r.RequestDigest, ObservedAt: now.Time, ValidUntil: end}
		after, err := q.CurrentTime(ctx)
		if err != nil || !out.Valid(peer, r, after.Time) {
			return authapp.ErrKeyDenied
		}
		return nil
	})
	if err != nil || ctx.Err() != nil {
		return authorization.KeyOperationPermit{}, authapp.ErrKeyDenied
	}
	return out, nil
}

// ContextKeyUnwrapGrantSQL is the exact privilege set of the verification
// unwrap authority's login (ADR-181).
func ContextKeyUnwrapGrantSQL(role string) []string {
	r := pgx.Identifier{role}.Sanitize()
	return []string{
		"GRANT USAGE ON SCHEMA public TO " + r,
		"GRANT SELECT ON goose_db_version TO " + r,
		"GRANT SELECT, UPDATE (installation_id) ON fleet_current_trust TO " + r,
		"GRANT SELECT (capture_id, root_id, attempt_id, expectation_digest, phase), UPDATE (capture_id) ON context_execution TO " + r,
		"GRANT SELECT (id, root_id, expectation_json) ON context_capture TO " + r,
		"GRANT SELECT (capture_id) ON context_catalog TO " + r,
		"GRANT SELECT, INSERT (attempt_id, root_id, last_certificate_sha256, unwraps), UPDATE (unwraps, last_certificate_sha256) ON context_key_unwrap TO " + r,
	}
}

// ContextPublicationQueue lists stored, unpublished captures for the
// publisher (ADR-181). A listing confers no publication authority.
type ContextPublicationQueue struct {
	ledger *Ledger
	root   string
}

func NewContextPublicationQueue(ctx context.Context, pool *pgxpool.Pool, root string) (*ContextPublicationQueue, error) {
	if !authorization.UUID(root) {
		return nil, artifact.ErrInvalid
	}
	ledger, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &ContextPublicationQueue{ledger, root}, nil
}

type PendingContextPublication struct {
	CaptureID, AttemptID string
	Copies               artifact.Copies
}

func (s *ContextPublicationQueue) PendingContextPublications(ctx context.Context, limit int) ([]PendingContextPublication, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || limit < 1 || limit > 64 {
		return nil, artifact.ErrInvalid
	}
	rows, err := custodydb.New(s.ledger.pool).ListContextPublicationQueue(ctx, custodydb.ListContextPublicationQueueParams{RootID: id(s.root), Limit: int32(limit)})
	if err != nil {
		return nil, privacy.ErrUnavailable
	}
	out := make([]PendingContextPublication, 0, len(rows))
	for _, row := range rows {
		var c artifact.Copies
		if json.Unmarshal(row.CopiesJson, &c) != nil {
			return nil, privacy.ErrUnavailable
		}
		out = append(out, PendingContextPublication{CaptureID: uid(row.CaptureID), AttemptID: uid(row.AttemptID), Copies: c})
	}
	return out, nil
}
