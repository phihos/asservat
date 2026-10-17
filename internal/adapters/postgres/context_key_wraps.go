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
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContextKeyWraps authorizes the artifact keyset wraps of one prepared API
// context execution (ADR-176). The authority ID is the attempt. Only the
// executor process's own activated connector client leaf may wrap, each of the
// three keyset roles at most once, before the execution's original deadline
// and before any start object exists. Spend is irreversible and never refunded.
type ContextKeyWraps struct {
	ledger   *Ledger
	root     string
	epoch    string // the protected key configuration's recovery epoch
	scope    authorization.KeyScope
	recovery *RecoveryReader
	guard    *RecoveryTransactionGuard
}

var _ authapp.KeyOperationAuthorizer = (*ContextKeyWraps)(nil)

// epoch is the installation recovery epoch of the key service's protected
// local key configuration (ADR-067); the key service rechecks it per effect.
func NewContextKeyWraps(ctx context.Context, pool *pgxpool.Pool, root, epoch string, scope authorization.KeyScope) (*ContextKeyWraps, error) {
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
	return &ContextKeyWraps{ledger: ledger, root: root, epoch: epoch, scope: scope, recovery: recovery, guard: guard}, nil
}

var contextKeyRoles = []string{"data-key", "index-key", "manifest-key"}

func (s *ContextKeyWraps) Resolve(ctx context.Context, peer authorization.KeyPeer, r authorization.KeyRequestInfo) (authorization.KeyOperationPermit, error) {
	var out authorization.KeyOperationPermit
	if s == nil || ctx == nil || ctx.Err() != nil || r.Scope != s.scope || r.Operation != "wrap" || !authorization.UUID(r.AuthorityID) || r.RequestDigest == (artifact.Digest{}) || len(r.Binding) < 1 || len(r.Binding) > 2048 || peer.Role != "collector" || !peer.CanRequest(s.scope, "wrap") {
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
		exec, err := q.ShareContextKeyWrapExecution(ctx, custodydb.ShareContextKeyWrapExecutionParams{AttemptID: id(r.AuthorityID), RootID: id(s.root)})
		if err != nil {
			return authapp.ErrKeyDenied
		}
		// Wrapping precedes the start CAS: only a still-prepared execution with
		// no start object, before its original deadline, may wrap.
		if exec.Phase != "prepared" || exec.ObjectUid.Valid || !now.Time.Before(exec.NotAfter.Time) || len(exec.ExpectationDigest) != 32 {
			return authapp.ErrKeyDenied
		}
		var e artifact.ContextExpectation
		var process execution.APIProcessBinding
		if json.Unmarshal(exec.ExpectationJson, &e) != nil || e.Validate() != nil || e.Registration.Location.AttemptID != r.AuthorityID || json.Unmarshal(exec.ProcessJson, &process) != nil || !process.Valid() {
			return authapp.ErrKeyDenied
		}
		digest := evidence.ContextExpectationDigest(e)
		if !bytes.Equal(digest[:], exec.ExpectationDigest) {
			return authapp.ErrKeyDenied
		}
		leaf, err := q.ReadActivatedConnectorClientLeaf(ctx, custodydb.ReadActivatedConnectorClientLeafParams{RootID: id(s.root), CertificateDigest: peer.Certificate[:]})
		if err != nil || uid(leaf.PodUid) != process.PodUID || uid(leaf.ClusterID) != process.ClusterID || uid(leaf.InstallationID) != s.scope.InstallationID || !now.Time.Before(leaf.CertificateNotAfter.Time) {
			return authapp.ErrKeyDenied
		}
		mask := int16(0)
		for i, role := range contextKeyRoles {
			binding, err := evidence.ArtifactKeyBinding(e.Binding(), role)
			if err != nil {
				return err
			}
			if bytes.Equal(binding, r.Binding) {
				mask = int16(1 << i)
			}
		}
		if mask == 0 {
			return authapp.ErrKeyDenied
		}
		spent, err := q.LockContextKeyWrap(ctx, custodydb.LockContextKeyWrapParams{AttemptID: id(r.AuthorityID), RootID: id(s.root)})
		var affected int64
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			affected, err = q.InsertContextKeyWrap(ctx, custodydb.InsertContextKeyWrapParams{AttemptID: id(r.AuthorityID), RootID: id(s.root), CertificateSha256: peer.Certificate[:], UsedRoles: mask})
		case err != nil:
			return err
		case !bytes.Equal(spent.CertificateSha256, peer.Certificate[:]) || spent.UsedRoles&mask != 0:
			return authapp.ErrKeyDenied
		default:
			affected, err = q.SpendContextKeyWrapRole(ctx, custodydb.SpendContextKeyWrapRoleParams{AttemptID: id(r.AuthorityID), RootID: id(s.root), CertificateSha256: peer.Certificate[:], RoleMask: mask})
		}
		if err != nil || affected != 1 {
			return authapp.ErrKeyDenied
		}
		if err = s.guard.check(ctx, q, trust, s.root, proof); err != nil {
			return err
		}
		end := identity.Earlier(exec.NotAfter.Time, leaf.CertificateNotAfter.Time)
		end = identity.Earlier(end, peer.NotAfter)
		end = identity.Earlier(end, identity.Earlier(start.Add(5*time.Second), proof.FreshUntil))
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

// ContextKeyWrapGrantSQL is the exact privilege set of the artifact wrap
// authority's login (ADR-176). Row locks need UPDATE on one immutable key; the
// tables' guard triggers still reject any change to it. The key-service role
// producer and owned fixtures share this list.
func ContextKeyWrapGrantSQL(role string) []string {
	r := pgx.Identifier{role}.Sanitize()
	return []string{
		"GRANT USAGE ON SCHEMA public TO " + r,
		"GRANT SELECT ON goose_db_version TO " + r,
		"GRANT SELECT, UPDATE (installation_id) ON fleet_current_trust TO " + r,
		"GRANT SELECT (capture_id, root_id, attempt_id, process_json, expectation_digest, not_after, phase, object_uid), UPDATE (capture_id) ON context_execution TO " + r,
		"GRANT SELECT (id, root_id, expectation_json) ON context_capture TO " + r,
		"GRANT SELECT (process_id, root_id, peer_id, certificate_digest, usage, activated_at, detached_at, certificate_not_after) ON connector_credential_attempt TO " + r,
		"GRANT SELECT (id, root_id, pod_uid, process_epoch, serving, retired_at) ON connector_identity_process TO " + r,
		"GRANT SELECT (root_id, peer_id, cluster_id, installation_id, configuration, suspended, blocked) ON connector_identity_profile TO " + r,
		"GRANT SELECT, INSERT (attempt_id, root_id, certificate_sha256, used_roles), UPDATE (used_roles) ON context_key_wrap TO " + r,
	}
}
