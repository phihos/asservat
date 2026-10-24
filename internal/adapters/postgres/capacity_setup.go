package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

type CapacitySetupRoot interface {
	ReadPublicRuntimeRoles(context.Context) (contracts.PublicRuntimeRoleSnapshot, error)
	ClaimCapacityRootSetup(context.Context, string, string, string, string, uint32, time.Time) (contracts.PublicRuntimeRoleSnapshot, bool, error)
	CompleteCapacityRootSetup(context.Context, contracts.PublicRuntimeRoleSnapshot, contracts.CapacityRootSetupReceipt) error
}

// InitializeCapacity belongs only to the existing protected post-activation
// SQL administrator producer. It cannot create roles, load replacement keys,
// accept a CRD source, fund a workload or clear the recovery fence. Ordinary
// capacity logins have no access to either INSERT used by this method.
func (s *PublicRuntimeSQLRoles) InitializeCapacity(ctx context.Context, input contracts.CapacityRootSetup, protection app.CapacitySourceProtectionReader) (_ contracts.CapacityRootSetupReceipt, err error) {
	var zero contracts.CapacityRootSetupReceipt
	// Fixed stage names and elapsed time for the operator stop message.
	started, at := time.Now(), "input"
	defer func() {
		if err != nil {
			err = &ProvisionStop{Step: "capacity/" + at + " after " + time.Since(started).Round(time.Millisecond).String(), Err: err}
		}
	}()
	if s == nil || protection == nil {
		return zero, cfg.ErrInvalid
	}
	in, err := decodeCapacitySetupInput(input, s.input)
	if err != nil {
		return zero, err
	}
	root, ok := s.root.(CapacitySetupRoot)
	if !ok {
		return zero, cfg.ErrInvalid
	}
	// No irreversible claim while a purpose or compartment is still reserved.
	for _, purpose := range contracts.CapacitySetupRolePurposes() {
		_, names := PublicRuntimeRoleName(s.input.InstallationID, purpose)
		_, grants := publicRuntimeRoleGrants(purpose)
		_, connections := contracts.PublicRuntimeRoleConnectionLimit(purpose)
		if !names || !grants || !connections {
			return zero, cfg.ErrUnavailable
		}
	}
	at = "enter"
	ctx, end, err := s.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer end()
	live, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	at = "current"
	database, postmaster, err := s.current(live, s.pool)
	if err != nil {
		return zero, err
	}
	at = "protection"
	p, err := protection.CapacityProtection(live)
	if err != nil || !capacitySetupProtection(in, p, time.Now()) {
		return zero, cfg.ErrUnavailable
	}
	live, stop := context.WithDeadline(live, p.FreshUntil)
	defer stop()
	// The retained static profile is immutable. Current admission dates are
	// selected later by the separately protected, purpose-separated phases.
	at = "prior-read"
	prior, err := root.ReadPublicRuntimeRoles(live)
	if err != nil || prior.UID != in.value.RoleRootUID || prior.State.OperationID != in.value.RoleSetupID || prior.State.MAC.AccountVersion != in.value.AccountVersion {
		return zero, cfg.ErrUnavailable
	}
	live, priorEnd := context.WithDeadline(live, prior.ValidUntil)
	defer priorEnd()
	at = "permission"
	preflightUntil, err := capacitySetupPermissionCurrent(live, s.pool, in)
	if err != nil {
		return zero, err
	}
	live, permissionEnd := context.WithDeadline(live, preflightUntil)
	defer permissionEnd()
	at = "preflight-roles"
	preflightRoles, err := s.capacitySetupRoles(live, s.pool, prior, database, postmaster)
	if err != nil {
		return zero, err
	}
	at = "static"
	if err = capacitySetupStaticSQL(live, s.pool, in, preflightRoles); err != nil {
		return zero, err
	}
	at = "claim"
	snapshot, fresh, err := root.ClaimCapacityRootSetup(live, in.value.RoleRootUID, in.value.RoleSetupID, in.value.PermissionRootID, in.digest, database, postmaster)
	if err != nil || !capacitySetupSnapshot(in, snapshot, database, postmaster) {
		return zero, cfg.ErrUnavailable
	}
	until := snapshot.ValidUntil
	if fresh {
		until = identity.Earlier(until, snapshot.State.CapacitySetup.Until)
	}
	live, narrow := context.WithDeadline(live, until)
	defer narrow()
	at = "transaction"
	receipt, err := s.capacitySetupTransaction(live, root, protection, in, snapshot, fresh, &at)
	if err != nil || live.Err() != nil {
		return zero, errors.Join(cfg.ErrUnavailable, err)
	}
	// Completion persistence is a separate bounded current observation. Its
	// only input is the exact committed receipt, not another SQL write permit.
	at = "complete"
	if err = root.CompleteCapacityRootSetup(ctx, snapshot, receipt); err != nil {
		return zero, cfg.ErrUnavailable
	}
	return receipt, nil
}

func capacitySetupProtection(in capacitySetupInput, p app.CapacitySourceProtection, n time.Time) bool {
	return p.Valid(n) && p.ClusterID == in.value.ControlClusterID && p.ControlNamespaceUID == in.value.ControlNamespaceUID && p.Digest == in.guard
}

func capacitySetupSnapshot(in capacitySetupInput, s contracts.PublicRuntimeRoleSnapshot, database uint32, postmaster time.Time) bool {
	c := s.State.CapacitySetup
	return s.UID == in.value.RoleRootUID && s.State.OperationID == in.value.RoleSetupID && s.State.Input.InstallationID == in.value.InstallationID && s.State.Input.InitialClaimID == in.value.InitialClaimID && s.State.MAC.AccountVersion == in.value.AccountVersion && c != nil && c.InputDigest == in.digest && c.PermissionRootID == in.value.PermissionRootID && c.DatabaseOID == database && c.PostmasterAt.Equal(postmaster)
}

func capacitySetupReceipt(in capacitySetupInput, s contracts.PublicRuntimeRoleSnapshot) contracts.CapacityRootSetupReceipt {
	c := s.State.CapacitySetup
	return contracts.CapacityRootSetupReceipt{Format: contracts.CapacityRootSetupFormat, OperationID: c.OperationID, InstallationID: in.value.InstallationID, InitialClaimID: in.value.InitialClaimID, PermissionRootID: in.value.PermissionRootID, RoleRootUID: s.UID, RoleSetupID: s.State.OperationID, InputDigest: in.digest, DatabaseOID: c.DatabaseOID, PostmasterAt: c.PostmasterAt, ClaimedAt: c.ClaimedAt, Until: c.Until}
}

func (s *PublicRuntimeSQLRoles) capacitySetupTransaction(ctx context.Context, root CapacitySetupRoot, protection app.CapacitySourceProtectionReader, in capacitySetupInput, original contracts.PublicRuntimeRoleSnapshot, fresh bool, at *string) (contracts.CapacityRootSetupReceipt, error) {
	var zero contracts.CapacityRootSetupReceipt
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	defer func() {
		c, e := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer e()
		_ = tx.Rollback(c)
	}()
	var locked string
	if err = tx.QueryRow(ctx, `SELECT installation_id::text FROM public.fleet_current_trust WHERE installation_id=$1 FOR SHARE`, in.value.InstallationID).Scan(&locked); err != nil || locked != in.value.InstallationID {
		return zero, cfg.ErrUnavailable
	}
	if err = tx.QueryRow(ctx, `SELECT id::text FROM public.permission_stream WHERE id=$1 FOR UPDATE`, in.value.PermissionRootID).Scan(&locked); err != nil || locked != in.value.PermissionRootID {
		return zero, cfg.ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1095979854,hashtext($1))`, in.value.InstallationID); err != nil {
		return zero, cfg.ErrUnavailable
	}
	// Every deadline returned after a blocking lock narrows all later reads,
	// effects and COMMIT. A later current observation cannot replace that bound.
	*at = "transaction/current"
	until, err := s.capacitySetupCurrent(ctx, tx, root, protection, in, original, fresh)
	if err != nil {
		return zero, err
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	*at = "transaction/roles"
	roles, err := s.capacitySetupRoles(ctx, tx, original, original.State.CapacitySetup.DatabaseOID, original.State.CapacitySetup.PostmasterAt)
	if err != nil {
		return zero, err
	}
	receipt := capacitySetupReceipt(in, original)
	if original.State.CapacitySetup.Receipt != nil && !reflect.DeepEqual(*original.State.CapacitySetup.Receipt, receipt) {
		return zero, cfg.ErrChanged
	}
	*at = "transaction/pair"
	if err = s.capacitySetupPair(ctx, tx, in, receipt, roles, fresh); err != nil {
		return zero, err
	}
	*at = "transaction/current-after"
	after, err := s.capacitySetupCurrent(ctx, tx, root, protection, in, original, fresh)
	if err != nil {
		return zero, err
	}
	until = identity.Earlier(until, after)
	final, finish := context.WithDeadline(ctx, until)
	defer finish()
	if final.Err() != nil || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	*at = "transaction/commit"
	if err = tx.Commit(final); err != nil || final.Err() != nil || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	return receipt, nil
}

func (s *PublicRuntimeSQLRoles) capacitySetupCurrent(ctx context.Context, tx pgx.Tx, root CapacitySetupRoot, protection app.CapacitySourceProtectionReader, in capacitySetupInput, original contracts.PublicRuntimeRoleSnapshot, fresh bool) (time.Time, error) {
	database, postmaster, err := s.current(ctx, tx)
	if err != nil || !capacitySetupSnapshot(in, original, database, postmaster) {
		return time.Time{}, cfg.ErrUnavailable
	}
	until, err := capacitySetupPermissionCurrent(ctx, tx, in)
	if err != nil {
		return time.Time{}, err
	}
	if fresh {
		until = identity.Earlier(until, original.State.CapacitySetup.Until)
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	next, err := root.ReadPublicRuntimeRoles(live)
	if err != nil || !capacitySetupSnapshot(in, next, database, postmaster) || !reflect.DeepEqual(next.State.Roles, original.State.Roles) {
		return time.Time{}, cfg.ErrUnavailable
	}
	a, b := *next.State.CapacitySetup, *original.State.CapacitySetup
	a.Receipt = nil
	b.Receipt = nil
	if !reflect.DeepEqual(a, b) {
		return time.Time{}, cfg.ErrChanged
	}
	until = identity.Earlier(until, next.ValidUntil)
	live, narrow := context.WithDeadline(live, until)
	defer narrow()
	p, err := protection.CapacityProtection(live)
	until = identity.Earlier(until, p.FreshUntil)
	if err != nil || !capacitySetupProtection(in, p, time.Now()) || live.Err() != nil || !time.Now().Before(until) {
		return time.Time{}, cfg.ErrUnavailable
	}
	return until, nil
}

func capacitySetupPermissionCurrent(ctx context.Context, q publicRoleQuery, in capacitySetupInput) (time.Time, error) {
	var until time.Time
	var valid bool
	err := q.QueryRow(ctx, `SELECT LEAST(t.fresh_until,p.fresh_until,p.lease_until),
 NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=clock_timestamp() AND NOT p.suspended AND p.observed_at<=clock_timestamp()
 AND p.fresh_until<=p.observed_at+interval '30 seconds'
 AND EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=p.initial_audit_id AND a.stream_id=p.id AND a.acknowledged_at IS NOT NULL)
 AND EXISTS(SELECT 1 FROM public.authority_audit a WHERE a.id=p.epoch AND a.stream_id=p.id AND a.acknowledged_at IS NOT NULL)
 FROM public.fleet_current_trust t CROSS JOIN public.permission_stream p WHERE t.installation_id=$1 AND p.id=$2`, in.value.InstallationID, in.value.PermissionRootID).Scan(&until, &valid)
	if err != nil || !valid || !time.Now().Before(until) {
		return time.Time{}, cfg.ErrUnavailable
	}
	return until, nil
}

type capacitySetupRole struct {
	Purpose    string
	Receipt    contracts.PublicRuntimeRoleReceipt
	Provenance publicRuntimeRoleProvenance
}

func (s *PublicRuntimeSQLRoles) capacitySetupRoles(ctx context.Context, tx publicRoleQuery, snapshot contracts.PublicRuntimeRoleSnapshot, database uint32, postmaster time.Time) ([]capacitySetupRole, error) {
	out := make([]capacitySetupRole, 0, 10)
	seen := map[uint32]bool{}
	for _, purpose := range contracts.CapacitySetupRolePurposes() {
		var material *contracts.PublicRuntimeRoleMaterial
		for i := range snapshot.State.Roles {
			if snapshot.State.Roles[i].Purpose == purpose {
				if material != nil {
					return nil, cfg.ErrChanged
				}
				material = &snapshot.State.Roles[i]
			}
		}
		if material == nil || material.Receipt == nil || material.Claim == nil || seen[material.Receipt.RoleOID] {
			return nil, cfg.ErrUnavailable
		}
		if material.Claim.DatabaseOID != database || !material.Claim.PostmasterAt.Equal(postmaster) {
			return nil, cfg.ErrChanged
		}
		name, known := PublicRuntimeRoleName(s.input.InstallationID, purpose)
		grants, fixed := publicRuntimeRoleGrants(purpose)
		connections, bounded := contracts.PublicRuntimeRoleConnectionLimit(purpose)
		if !known || !fixed || !bounded {
			return nil, cfg.ErrUnavailable
		}
		provenance := s.provenance(snapshot, purpose, *material.Claim)
		raw, err := json.Marshal(provenance)
		if err != nil {
			return nil, cfg.ErrUnavailable
		}
		receipt, err := verifyFixedRuntimeRole(ctx, tx, name, connections, s.input.LayoutDigest, material.Receipt, raw, grants)
		if err != nil {
			return nil, err
		}
		seen[receipt.RoleOID] = true
		out = append(out, capacitySetupRole{purpose, receipt, provenance})
	}
	return out, nil
}
