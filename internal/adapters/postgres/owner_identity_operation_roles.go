package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

func (s *OwnerIdentityOperationSQL) ReadOwnerIdentityRoleIncarnation(ctx context.Context) (uint32, time.Time, error) {
	if s == nil || s.roles == nil || s.root == nil {
		return 0, time.Time{}, cfg.ErrUnavailable
	}
	call, end, err := s.roles.enter(ctx)
	if err != nil {
		return 0, time.Time{}, err
	}
	defer end()
	return s.roles.current(call, s.roles.pool)
}

// AdvanceOwnerIdentityRoleOperation either spends this call's original positive
// native admission once, or independently inspects an existing claim. The SQL
// result of fresh CREATE is pending, never a fabricated credential receipt.
func (s *OwnerIdentityOperationSQL) AdvanceOwnerIdentityRoleOperation(ctx context.Context, operation *kubernetes.OwnerIdentityOperation) (kubernetes.OwnerIdentityRoleAdvance, error) {
	return s.advanceOwnerIdentityRoleOperation(ctx, operation, false)
}

func (s *OwnerIdentityOperationSQL) InspectOwnerIdentityRoleOperation(ctx context.Context, operation *kubernetes.OwnerIdentityOperation) (kubernetes.OwnerIdentityRoleAdvance, error) {
	return s.advanceOwnerIdentityRoleOperation(ctx, operation, true)
}

func (s *OwnerIdentityOperationSQL) advanceOwnerIdentityRoleOperation(ctx context.Context, operation *kubernetes.OwnerIdentityOperation, inspect bool) (_ kubernetes.OwnerIdentityRoleAdvance, failure error) {
	check := ownerProjectionSQLEntry
	defer func() {
		if failure != nil {
			failure = &OwnerProjectionSQLFailure{check: check, cause: failure}
		}
	}()
	var zero kubernetes.OwnerIdentityRoleAdvance
	if s == nil || s.roles == nil || s.root == nil || operation == nil {
		return zero, cfg.ErrUnavailable
	}
	call, leave, err := s.roles.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer leave()
	check = ownerIdentityRoleSQLAdmitted
	initial, err := operation.AdmittedOwnerIdentityRoles(call, s.root)
	if err != nil || initial.State.Input != s.roles.input || len(initial.State.Roles) != len(contracts.OwnerIdentityRolePurposes()) {
		return zero, cfg.ErrUnavailable
	}
	until := initial.ValidUntil
	call, stop := context.WithDeadline(call, until)
	defer stop()
	check = ownerIdentityRoleSQLBegin
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
	check = ownerIdentityRoleSQLLocks
	if err = tx.QueryRow(call, `SELECT installation_id::text FROM public.fleet_current_trust WHERE installation_id=$1 FOR SHARE`, s.roles.input.InstallationID).Scan(&locked); err != nil || locked != s.roles.input.InstallationID {
		return zero, cfg.ErrUnavailable
	}
	if _, err = tx.Exec(call, `SELECT pg_advisory_xact_lock(1095979854,hashtext($1))`, s.roles.input.InstallationID); err != nil {
		return zero, cfg.ErrUnavailable
	}
	check = ownerIdentityRoleSQLCurrentBefore
	database, postmaster, err := s.roles.current(call, tx)
	if err != nil {
		return zero, err
	}
	check = ownerIdentityRoleSQLAfterLock
	current, err := operation.ReadOwnerIdentityRolesAfterLock(call, s.root)
	if err != nil || !ownerIdentityOperationSameSnapshot(initial, current) {
		return zero, cfg.ErrUnavailable
	}
	until = identity.Earlier(until, current.ValidUntil)
	call, narrow := context.WithDeadline(call, until)
	defer narrow()
	check = ownerIdentityRoleSQLAttempt
	purpose, fresh, err := operation.OwnerIdentityRoleAttempt(call, s.root)
	index := slices.Index(contracts.OwnerIdentityRolePurposes(), purpose)
	if err != nil || index < 0 || current.State.Roles[index].Claim == nil || inspect && fresh {
		return zero, cfg.ErrUnavailable
	}
	check = ownerIdentityRoleSQLClaim
	material := current.State.Roles[index]
	claim := *material.Claim
	if fresh {
		until = identity.Earlier(until, identity.Earlier(claim.Until, current.State.Until))
		if material.Receipt != nil || claim.DatabaseOID != database || !claim.PostmasterAt.Equal(postmaster) {
			return zero, cfg.ErrChanged
		}
	}
	call, effectBound := context.WithDeadline(call, until)
	defer effectBound()
	if call.Err() != nil || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	name, known := OwnerIdentityRoleName(s.roles.input.InstallationID, purpose)
	grants, fixed := ownerIdentityRoleGrants(purpose)
	if !known || !fixed {
		return zero, cfg.ErrInvalid
	}
	provenance, err := json.Marshal(s.roles.provenance(current, purpose, claim))
	defer clear(provenance)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	var oid uint32
	err = tx.QueryRow(call, `SELECT oid FROM pg_roles WHERE rolname=$1`, name).Scan(&oid)
	if errors.Is(err, pgx.ErrNoRows) {
		check = ownerIdentityRoleSQLCreate
		if !fresh {
			return zero, cfg.ErrUnavailable
		}
		verifier, err := initialPasswordVerifier(InitialSQLLogin{Username: name, Password: material.Password})
		if err != nil {
			return zero, err
		}
		if _, _, err = s.roles.current(call, tx); err != nil || call.Err() != nil || !time.Now().Before(until) {
			return zero, cfg.ErrUnavailable
		}
		if err = operation.BeginOwnerIdentityRoleCreate(call, s.root); err != nil {
			return zero, err
		}
		if _, err = tx.Exec(call, "CREATE ROLE "+pgx.Identifier{name}.Sanitize()+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT "+strconv.Itoa(contracts.OwnerIdentityRoleConnections)+" PASSWORD '"+verifier+"'"); err != nil {
			return zero, cfg.ErrUnavailable
		}
		for _, grant := range grants {
			if _, err = tx.Exec(call, grant.sql(name)); err != nil {
				return zero, cfg.ErrUnavailable
			}
		}
		if _, err = tx.Exec(call, "REVOKE "+pgx.Identifier{name}.Sanitize()+" FROM "+pgx.Identifier{s.roles.pool.Config().ConnConfig.User}.Sanitize()); err != nil {
			return zero, cfg.ErrUnavailable
		}
		if _, err = tx.Exec(call, "COMMENT ON ROLE "+pgx.Identifier{name}.Sanitize()+" IS "+quoteSQLLiteral(string(provenance))); err != nil {
			return zero, cfg.ErrUnavailable
		}
	} else if err != nil {
		return zero, cfg.ErrUnavailable
	} else if fresh {
		check = ownerIdentityRoleSQLExisting
		return zero, cfg.ErrChanged
	}
	check = ownerIdentityRoleSQLVerify
	receipt, err := s.roles.verify(call, tx, material, provenance)
	if err != nil {
		return zero, err
	}
	status := kubernetes.OwnerIdentityRoleAdvancePending
	if !fresh {
		// Only an independently observed committed role can be authenticated.
		// Keep the role lock through this bounded login and receipt publication.
		check = ownerIdentityRoleSQLAuthenticate
		if err = s.roles.authenticate(call, material, receipt); err != nil {
			return zero, err
		}
		if !inspect {
			check = ownerIdentityRoleSQLAcknowledge
			current, err = operation.AcknowledgeOwnerIdentityRole(call, s.root, receipt)
			if err != nil {
				return zero, err
			}
			until = identity.Earlier(until, current.ValidUntil)
			status = kubernetes.OwnerIdentityRoleAdvanceComplete
		} else if material.Receipt != nil {
			status = kubernetes.OwnerIdentityRoleAdvanceComplete
		}
	}
	check = ownerIdentityRoleSQLFinalRead
	final, err := operation.ReadOwnerIdentityRolesFinal(call, s.root)
	if err != nil || !ownerIdentityOperationSameSnapshot(current, final) {
		return zero, cfg.ErrUnavailable
	}
	until = identity.Earlier(until, final.ValidUntil)
	call, finalBound := context.WithDeadline(call, until)
	defer finalBound()
	check = ownerIdentityRoleSQLCurrentAfter
	if _, _, err = s.roles.current(call, tx); err != nil || call.Err() != nil || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	check = ownerIdentityRoleSQLCommit
	if err = tx.Commit(call); err != nil || call.Err() != nil || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	final.ValidUntil = until
	return kubernetes.OwnerIdentityRoleAdvance{Status: status, Snapshot: final}, nil
}
