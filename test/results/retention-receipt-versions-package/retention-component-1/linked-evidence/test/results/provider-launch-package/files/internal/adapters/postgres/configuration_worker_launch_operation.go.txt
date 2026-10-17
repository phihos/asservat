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

// WithConfigurationWorkerLaunchOperation is the fixed original three-role SQL
// boundary for the fresh worker2 launch state machine. The concrete original
// native root and opaque operation own their named phases. This method accepts
// neither an authority callback nor a caller-created native observation.
func (s *ConfigurationRuntimeSQLRoles) WithConfigurationWorkerLaunchOperation(ctx context.Context, operation *kube.ConfigurationWorkerLaunchOperation) error {
	call, finish, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer finish()
	root, ok := s.root.(*kube.ConfigurationRuntimeRoleRoot)
	if !ok || operation == nil {
		return cfg.ErrUnavailable
	}
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
	snapshot, err := operation.ReadConfigurationWorkerLaunchPostLock(bounded, root)
	if err != nil {
		return err
	}
	if snapshot.State.Input != s.input || len(snapshot.State.Roles) != len(contracts.ConfigurationRuntimeRolePurposes()) {
		return cfg.ErrUnavailable
	}
	claimsSource, ok := configurationWorkerLaunchClaimsSource(snapshot)
	if !ok {
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
		if material.Claim == nil || material.Receipt == nil || !sameConfigurationRoleSource(claimsSource, material.Claim.Sources) {
			return cfg.ErrUnavailable
		}
		encoded, e := json.Marshal(s.provenance(snapshot, material.Purpose, *material.Claim))
		if e != nil {
			return cfg.ErrUnavailable
		}
		if _, err = s.verify(bounded, tx, material, encoded); err != nil {
			return err
		}
	}
	if err = operation.ApplyConfigurationWorkerLaunchEffect(bounded, root, snapshot); err != nil {
		return err
	}
	last, err := operation.ReadConfigurationWorkerLaunchFinal(bounded, root)
	if err != nil {
		return err
	}
	finalSource, ok := configurationWorkerLaunchClaimsSource(last)
	if !ok || last.UID != snapshot.UID || !sameConfigurationRoleSource(finalSource, claimsSource) || !configurationWorkerLaunchSameOriginal(snapshot.State, last.State) {
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
	return operation.CompleteConfigurationWorkerLaunch(bounded, root)
}

// Exact permitted workload transition only. The concrete native operation has
// independently checked the complete actual Deployment, mount and claim; this
// SQL comparison retains every original role provenance and source date.
func configurationWorkerLaunchClaimsSource(v contracts.ConfigurationRuntimeRoleSnapshot) (contracts.ConfigurationRoleObservation, bool) {
	current := v.Sources
	l := v.State.Launch
	if l == nil || v.State.Projection == nil || v.State.Projection.SecretUID != l.ProjectionUID || l.RunningDigest == l.Sources.WorkloadDigest {
		return contracts.ConfigurationRoleObservation{}, false
	}
	if current.WorkloadDigest != l.Sources.WorkloadDigest && current.WorkloadDigest != l.RunningDigest {
		return contracts.ConfigurationRoleObservation{}, false
	}
	current.WorkloadDigest = l.Sources.WorkloadDigest
	return current, sameConfigurationRoleSource(current, l.Sources)
}

func configurationWorkerLaunchSameOriginal(a, b contracts.ConfigurationRuntimeRoleState) bool {
	if a.Launch == nil || b.Launch == nil {
		return false
	}
	aa, bb := *a.Launch, *b.Launch
	if aa.Receipt != nil && (bb.Receipt == nil || *aa.Receipt != *bb.Receipt) {
		return false
	}
	aa.Receipt = nil
	bb.Receipt = nil
	a.Launch = &aa
	b.Launch = &bb
	x, e := json.Marshal(a)
	if e != nil {
		return false
	}
	defer clear(x)
	y, e := json.Marshal(b)
	if e != nil {
		return false
	}
	defer clear(y)
	return string(x) == string(y)
}
