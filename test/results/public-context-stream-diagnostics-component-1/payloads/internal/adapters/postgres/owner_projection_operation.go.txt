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

// AdvanceOwnerProjectionOperation holds the existing recovery/installation
// locks through actual post-lock values, exact four-role SQL verification, one
// fixed native phase and its independent final proof. Provider inspection has
// already finished outside these locks. No generic callback enters SQL.
func (s *OwnerIdentityOperationSQL) AdvanceOwnerProjectionOperation(ctx context.Context, operation *kubernetes.OwnerProjectionOperation) (result kubernetes.OwnerProjectionAdvance, failure error) {
	check := ownerProjectionSQLEntry
	reason := ownerProjectionSQLReasonUnspecified
	defer func() {
		if failure != nil {
			failure = &OwnerProjectionSQLFailure{check: check, reason: reason, cause: failure}
		}
	}()
	var zero kubernetes.OwnerProjectionAdvance
	if s == nil || s.roles == nil || s.root == nil || operation == nil {
		return zero, cfg.ErrUnavailable
	}
	check = ownerProjectionSQLLifetime
	call, leave, err := s.roles.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer leave()
	// Zero, copied, stale, cross-root and cross-call handles fail before pool
	// acquisition or any SQL/native I/O. This is the original pre-lock result.
	check = ownerProjectionSQLAdmitted
	initial, err := operation.AdmittedOwnerIdentityRoles(call, s.root)
	if err != nil || initial.State.Input != s.roles.input || len(initial.State.Roles) != len(contracts.OwnerIdentityRolePurposes()) {
		return zero, cfg.ErrUnavailable
	}
	until := initial.ValidUntil
	call, stop := context.WithDeadline(call, until)
	defer stop()
	check = ownerProjectionSQLBegin
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
	check = ownerProjectionSQLFleetLock
	if operation.OwnerProjectionExecutionOnly() {
		var version int64
		err = tx.QueryRow(call, ownerProjectionVersionLockSQL, s.roles.input.InstallationID).Scan(&locked, &version)
		if err != nil || locked != s.roles.input.InstallationID || operation.BindOwnerProjectionSemanticVersion(call, s.root, version) != nil {
			return zero, cfg.ErrUnavailable
		}
	} else if err = tx.QueryRow(call, `SELECT installation_id::text FROM public.fleet_current_trust WHERE installation_id=$1 FOR SHARE`, s.roles.input.InstallationID).Scan(&locked); err != nil || locked != s.roles.input.InstallationID {
		return zero, cfg.ErrUnavailable
	}
	check = ownerProjectionSQLInstallationLock
	if _, err = tx.Exec(call, `SELECT pg_advisory_xact_lock(1095979854,hashtext($1))`, s.roles.input.InstallationID); err != nil {
		return zero, cfg.ErrUnavailable
	}
	check = ownerProjectionSQLCurrentBeforeNative
	if _, _, err = s.roles.current(call, tx); err != nil {
		return zero, err
	}
	check = ownerProjectionSQLCurrentNative
	current, err := operation.ReadOwnerProjectionAfterLock(call, s.root)
	if err != nil || !ownerIdentityOperationSameSnapshot(initial, current) {
		return zero, cfg.ErrUnavailable
	}
	until = identity.Earlier(until, current.ValidUntil)
	call, narrow := context.WithDeadline(call, until)
	defer narrow()
	check = ownerProjectionSQLCurrentDeadline
	if call.Err() != nil || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	for _, material := range current.State.Roles {
		check = ownerProjectionSQLRoleMaterial
		if material.Claim == nil || material.Receipt == nil {
			return zero, cfg.ErrUnavailable
		}
		check = ownerProjectionSQLRoleProvenance
		provenance, err := json.Marshal(s.roles.provenance(current, material.Purpose, *material.Claim))
		if err != nil {
			return zero, cfg.ErrUnavailable
		}
		check = ownerProjectionSQLRoleVerification
		_, err = s.roles.verify(call, tx, material, provenance)
		clear(provenance)
		if err != nil {
			return zero, err
		}
	}
	// The current role/source/interval checks precede the one fixed native effect.
	check = ownerProjectionSQLCurrentBeforeEffect
	if _, _, err = s.roles.current(call, tx); err != nil || call.Err() != nil || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	check = ownerProjectionSQLApply
	if err = operation.ApplyOwnerProjection(call, s.root); err != nil {
		return zero, err
	}
	if operation.OwnerProjectionExecutionOnly() {
		check = ownerProjectionSQLCurrentAfterFinal
		_, _, err = s.roles.current(call, tx)
		if reason = ownerProjectionFinalCurrentReason(call, err, until, time.Now); reason != ownerProjectionSQLReasonUnspecified {
			return zero, cfg.ErrUnavailable
		}
		check = ownerProjectionSQLCommit
		if err = tx.Commit(call); err != nil || call.Err() != nil || !time.Now().Before(until) {
			return zero, cfg.ErrUnavailable
		}
		check = ownerProjectionSQLResult
		return operation.OwnerProjectionExecutionResult(call, s.root)
	}
	check = ownerProjectionSQLFinalNative
	final, err := operation.ReadOwnerProjectionFinal(call, s.root)
	if err != nil || !ownerIdentityOperationSameSnapshot(initial, final) {
		return zero, cfg.ErrUnavailable
	}
	until = identity.Earlier(until, final.ValidUntil)
	call, finalBound := context.WithDeadline(call, until)
	defer finalBound()
	check = ownerProjectionSQLCurrentAfterFinal
	_, _, err = s.roles.current(call, tx)
	if reason = ownerProjectionFinalCurrentReason(call, err, until, time.Now); reason != ownerProjectionSQLReasonUnspecified {
		return zero, cfg.ErrUnavailable
	}
	check = ownerProjectionSQLCommit
	if err = tx.Commit(call); err != nil || call.Err() != nil || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	check = ownerProjectionSQLResult
	return operation.OwnerProjectionResult(call, s.root)
}
