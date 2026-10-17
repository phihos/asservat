package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

// OwnerIdentityOperationSQL is the fresh installer adapter's fixed native/SQL
// boundary. This deliberate C21 -> C21 edge accepts only the concrete native
// root and its operation-owned handle; it is not another source authority port.
// The unchanged legacy producer remains available to its original callers.
type OwnerIdentityOperationSQL struct {
	roles *OwnerIdentitySQLRoles
	root  *kubernetes.OwnerIdentityRoleRoot
}

func NewOwnerIdentityOperationSQL(ctx context.Context, config *pgx.ConnConfig, root *kubernetes.OwnerIdentityRoleRoot, input contracts.OwnerIdentityRoles) (*OwnerIdentityOperationSQL, error) {
	if root == nil || input.OwnerLayout != contracts.OwnerProviderInstalledLayout || root.Input() != input || !validOwnerIdentityRoleInput(input) {
		return nil, cfg.ErrInvalid
	}
	// That constructor performs only purpose-local SQL checks; it does not call
	// the legacy amplified native reader, create a role, or adopt a root.
	roles, err := NewOwnerIdentitySQLRoles(ctx, config, root, input)
	if err != nil {
		return nil, err
	}
	return &OwnerIdentityOperationSQL{roles: roles, root: root}, nil
}

func (s *OwnerIdentityOperationSQL) Close() {
	if s != nil && s.roles != nil {
		s.roles.Close()
	}
}

// VerifyOwnerIdentityOperation retains recovery + role locks through actual
// post-lock native reads, exact four-role verification, a genuinely independent
// final native bracket and the final SQL incarnation check. There are no role
// or Kubernetes mutations in this method.
func (s *OwnerIdentityOperationSQL) VerifyOwnerIdentityOperation(ctx context.Context, operation *kubernetes.OwnerIdentityOperation) (contracts.OwnerIdentityRoleSnapshot, error) {
	var zero contracts.OwnerIdentityRoleSnapshot
	if s == nil || s.roles == nil || s.root == nil || operation == nil {
		return zero, cfg.ErrUnavailable
	}
	call, leave, err := s.roles.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer leave()
	// Zero, copied, stale, cross-root and cross-call handles fail before pool
	// acquisition or any SQL/native I/O. This is the original pre-lock result.
	initial, err := operation.AdmittedOwnerIdentityRoles(call, s.root)
	if err != nil || initial.State.Input != s.roles.input || len(initial.State.Roles) != len(contracts.OwnerIdentityRolePurposes()) {
		return zero, cfg.ErrUnavailable
	}
	until := initial.ValidUntil
	call, stop := context.WithDeadline(call, until)
	defer stop()
	tx, err := s.roles.pool.BeginTx(call, pgx.TxOptions{})
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	defer func() {
		rollback, end := context.WithTimeout(context.WithoutCancel(call), time.Second)
		defer end()
		_ = tx.Rollback(rollback)
	}()
	var locked string
	if err = tx.QueryRow(call, `SELECT installation_id::text FROM public.fleet_current_trust WHERE installation_id=$1 FOR SHARE`, s.roles.input.InstallationID).Scan(&locked); err != nil || locked != s.roles.input.InstallationID {
		return zero, cfg.ErrUnavailable
	}
	if _, err = tx.Exec(call, `SELECT pg_advisory_xact_lock(1095979854,hashtext($1))`, s.roles.input.InstallationID); err != nil {
		return zero, cfg.ErrUnavailable
	}
	if _, _, err = s.roles.current(call, tx); err != nil {
		return zero, err
	}
	current, err := operation.ReadOwnerIdentityRolesAfterLock(call, s.root)
	if err != nil || !ownerIdentityOperationSameSnapshot(initial, current) {
		return zero, cfg.ErrUnavailable
	}
	until = identity.Earlier(until, current.ValidUntil)
	call, narrow := context.WithDeadline(call, until)
	defer narrow()
	if call.Err() != nil || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	for _, material := range current.State.Roles {
		if material.Claim == nil || material.Receipt == nil {
			return zero, cfg.ErrUnavailable
		}
		provenance, err := json.Marshal(s.roles.provenance(current, material.Purpose, *material.Claim))
		if err != nil {
			return zero, cfg.ErrUnavailable
		}
		_, err = s.roles.verify(call, tx, material, provenance)
		clear(provenance)
		if err != nil {
			return zero, err
		}
	}
	final, err := operation.ReadOwnerIdentityRolesFinal(call, s.root)
	if err != nil || !ownerIdentityOperationSameSnapshot(initial, final) {
		return zero, cfg.ErrUnavailable
	}
	until = identity.Earlier(until, final.ValidUntil)
	call, finalBound := context.WithDeadline(call, until)
	defer finalBound()
	if _, _, err = s.roles.current(call, tx); err != nil || call.Err() != nil || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	if err = tx.Commit(call); err != nil || call.Err() != nil || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	final.ValidUntil = until
	return final, nil
}

func ownerIdentityOperationSameSnapshot(a, b contracts.OwnerIdentityRoleSnapshot) bool {
	return a.UID == b.UID && a.ResourceVersion == b.ResourceVersion && ownerIdentitySnapshotStateEqual(a.State, b.State)
}
