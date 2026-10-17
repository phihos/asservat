package postgres

import (
	"context"
	"encoding/json"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
)

// WithConfigurationWorkerOperation is only the fresh installer configuration
// path. It consumes an opaque operation minted by the exact original concrete
// native root's worker producer; it does not accept a timestamp proof or a
// caller-provided authority callback. Legacy generic verification is unchanged.
func (s *ConfigurationRuntimeSQLRoles) WithConfigurationWorkerOperation(ctx context.Context, operation *kube.ConfigurationWorkerOperation) error {
	call, finish, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer finish()
	root, ok := s.root.(*kube.ConfigurationRuntimeRoleRoot)
	if !ok || operation == nil {
		return cfg.ErrUnavailable
	}
	// The outer worker/bridge end covers provider work and every prior native
	// request. This can only shorten it, never start another effect window.
	bounded, stop := context.WithTimeout(call, 5*time.Second)
	defer stop()
	until, _ := bounded.Deadline()
	tx, err := s.pool.BeginTx(bounded, pgx.TxOptions{})
	if err != nil {
		return cfg.ErrUnavailable
	}
	defer func() {
		rollback, end := context.WithTimeout(context.WithoutCancel(bounded), time.Second)
		defer end()
		_ = tx.Rollback(rollback)
	}()
	var installation string
	if err = tx.QueryRow(bounded, `SELECT installation_id::text FROM public.fleet_current_trust WHERE installation_id=$1 FOR SHARE`, s.input.InstallationID).Scan(&installation); err != nil || installation != s.input.InstallationID {
		return cfg.ErrUnavailable
	}
	if _, err = tx.Exec(bounded, `SELECT pg_advisory_xact_lock(1095979854,hashtext($1))`, s.input.InstallationID); err != nil {
		return cfg.ErrUnavailable
	}
	if _, _, err = s.current(bounded, tx); err != nil {
		return err
	}
	// This named method makes sixteen actual native value reads after both
	// blocking locks. It cannot return the earlier pre-lock snapshot instead.
	snapshot, err := operation.ReadConfigurationWorkerPostLock(bounded, root)
	if err != nil {
		return err
	}
	if snapshot.State.Input != s.input || snapshot.State.Launch != nil || len(snapshot.State.Roles) != len(contracts.ConfigurationRuntimeRolePurposes()) {
		return cfg.ErrUnavailable
	}
	if snapshot.ValidUntil.Before(until) {
		until = snapshot.ValidUntil
	}
	bounded, narrow := context.WithDeadline(bounded, until)
	defer narrow()
	if bounded.Err() != nil || !time.Now().Before(until) {
		return cfg.ErrUnavailable
	}
	if err = s.currentSources(bounded, tx, snapshot.Sources); err != nil {
		return err
	}
	for _, material := range snapshot.State.Roles {
		if material.Claim == nil || material.Receipt == nil || !sameConfigurationRoleSource(snapshot.Sources, material.Claim.Sources) {
			return cfg.ErrUnavailable
		}
		encoded, err := json.Marshal(s.provenance(snapshot, material.Purpose, *material.Claim))
		if err != nil {
			return cfg.ErrUnavailable
		}
		if _, err = s.verify(bounded, tx, material, encoded); err != nil {
			return err
		}
	}
	if err = operation.ApplyConfigurationWorkerEffect(bounded, root, snapshot); err != nil {
		return err
	}
	last, err := operation.ReadConfigurationWorkerFinal(bounded, root)
	if err != nil {
		return err
	}
	if last.UID != snapshot.UID || last.ResourceVersion != snapshot.ResourceVersion || !sameConfigurationRoleSource(last.Sources, snapshot.Sources) {
		return cfg.ErrChanged
	}
	if last.ValidUntil.Before(until) {
		until = last.ValidUntil
	}
	bounded, finalEnd := context.WithDeadline(bounded, until)
	defer finalEnd()
	if _, _, err = s.current(bounded, tx); err != nil || bounded.Err() != nil || !time.Now().Before(until) {
		return cfg.ErrUnavailable
	}
	if err = s.currentSources(bounded, tx, last.Sources); err != nil {
		return err
	}
	if err = tx.Commit(bounded); err != nil || bounded.Err() != nil || !time.Now().Before(until) {
		return cfg.ErrUnavailable
	}
	return operation.CompleteConfigurationWorkerOperation(bounded, root)
}
