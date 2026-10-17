package postgres

import (
	"context"
	"encoding/json"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Retire is invoked only after the supervisor's completed handover and joined
// preparation pool. It independently rechecks the same positive SQL activation
// record. The protected seed's Closing is sequencing, never evidence of SQL
// revocation. A persisted SQL completion is readable after its original cleanup
// deadline; missing completion can never be inferred from expiry.
func (s *InitialSQLManager) Retire(ctx context.Context, history app.InitialInstallationHistory) (time.Time, error) {
	if history == nil {
		return time.Time{}, cfg.ErrInvalid
	}
	bounded, end, e := s.enter(ctx)
	if e != nil {
		return time.Time{}, e
	}
	defer end()
	state, until, e := s.root.ReadBootstrapSQLManager(bounded)
	if e != nil || !initialManagerState(state) || state.Manager.Receipt == nil || state.Manager.Closing == nil || state.Retired || !time.Now().Before(until) {
		return time.Time{}, cfg.ErrUnavailable
	}
	bounded, stop := context.WithDeadline(bounded, until)
	defer stop()
	h, e := history.ObserveInitialInstallation(bounded)
	if e != nil || h.Disposition != app.InitialInstallationActivated || h.Record == nil || h.AuditReceipt == nil || h.Record.Scope.InstallationID != state.InstallationID || h.Record.Scope.ClusterID != state.ClusterID || h.Record.Scope.IssuerEpoch != state.IssuerEpoch || !time.Now().Before(h.ValidUntil) {
		return time.Time{}, cfg.ErrChanged
	}
	bounded, stop = context.WithDeadline(bounded, h.ValidUntil)
	defer stop()
	// The marker is written only after flags/grants/session closure and actual
	// login rejection. An unknown final COMMIT can be resolved without replay.
	if completed, e := s.readManagerRetirement(bounded, state); e == nil && !completed.IsZero() {
		if e = s.verifyManagerClosed(bounded, state, completed, h); e != nil {
			return time.Time{}, e
		}
		return completed, nil
	} else if e != nil {
		return time.Time{}, e
	}
	closing := state.Manager.Closing
	if !time.Now().Before(closing.Until) {
		return time.Time{}, cfg.ErrUnavailable
	}
	bounded, stop = context.WithDeadline(bounded, closing.Until)
	defer stop()
	bounded, stop, e = s.current(bounded, state)
	if e != nil {
		return time.Time{}, e
	}
	defer stop()
	e = s.transaction(bounded, state, func(ctx context.Context, tx pgx.Tx) error {
		if e = s.managerCleanupDatabase(ctx, tx, state, true); e != nil {
			return e
		}
		if e = checkManagerActivation(ctx, tx, state, h); e != nil {
			return e
		}
		// Keep native effect-table lock order. The independently joined process
		// cannot acquire new authority; all final checks still use original time.
		if e = lockInitialTables(ctx, tx); e != nil {
			return cfg.ErrUnavailable
		}
		if e = s.managerCleanupDatabase(ctx, tx, state, true); e != nil {
			return e
		}
		if _, e = s.checkRole(ctx, tx, state, true); e == nil {
			if e = checkInitialManagerGrants(ctx, tx, state.Manager.Receipt.OID, true); e != nil {
				return e
			}
			return verifyTransferredHistory(ctx, tx, state)
		}
		original := managerStateWithoutClose(state)
		if _, e = s.checkRole(ctx, tx, original, false); e != nil {
			return e
		}
		if e = checkInitialManagerGrants(ctx, tx, state.Manager.Receipt.OID, false); e != nil {
			return e
		}
		if e = transferInitialHistoryGrants(ctx, tx, state); e != nil {
			return e
		}
		// LOGIN flags do not close already authenticated SQL sessions.
		if _, e = tx.Exec(ctx, "ALTER ROLE "+pgx.Identifier{state.Manager.Receipt.Name}.Sanitize()+" NOLOGIN NOCREATEROLE PASSWORD NULL"); e != nil {
			return cfg.ErrUnavailable
		}
		for _, g := range initialBootstrapManagerGrants() {
			if _, e = tx.Exec(ctx, g.sql("REVOKE", state.Manager.Receipt.Name)+" RESTRICT"); e != nil {
				return cfg.ErrUnavailable
			}
		}
		if e = writeInitialManagerComment(ctx, tx, state.Manager.Receipt.Name, initialManagerRecord(state)); e != nil {
			return e
		}
		if _, e = s.checkRole(ctx, tx, state, true); e != nil {
			return e
		}
		if e = checkInitialManagerGrants(ctx, tx, state.Manager.Receipt.OID, true); e != nil {
			return e
		}
		if e = verifyTransferredHistory(ctx, tx, state); e != nil {
			return e
		}
		return s.managerCleanupDatabase(ctx, tx, state, true)
	})
	if e != nil {
		return time.Time{}, e
	}
	if e = s.terminateManagerSessions(bounded, state); e != nil {
		return time.Time{}, e
	}
	if e = s.checkPassword(bounded, state, true); e != nil {
		return time.Time{}, e
	}
	final, done, e := s.current(bounded, state)
	if e != nil {
		return time.Time{}, e
	}
	defer done()
	var completed time.Time
	e = s.transaction(final, state, func(ctx context.Context, tx pgx.Tx) error {
		if e = s.managerCleanupDatabase(ctx, tx, state, true); e != nil {
			return e
		}
		if e = checkManagerActivation(ctx, tx, state, h); e != nil {
			return e
		}
		if _, e = s.checkRole(ctx, tx, state, true); e != nil {
			return e
		}
		if e = checkInitialManagerGrants(ctx, tx, state.Manager.Receipt.OID, true); e != nil {
			return e
		}
		if e = verifyTransferredHistory(ctx, tx, state); e != nil {
			return e
		}
		if e = managerSessionsAbsent(ctx, tx, state.Manager.Receipt.OID); e != nil {
			return e
		}
		_, _, completed, e = s.database(ctx, tx)
		if e != nil || completed.Before(closing.StartedAt) || !completed.Before(closing.Until) {
			return cfg.ErrUnavailable
		}
		record := initialManagerRecord(state)
		record.RetiredAt = &completed
		return writeInitialManagerComment(ctx, tx, state.Manager.Receipt.Name, record)
	})
	if e != nil {
		return time.Time{}, e
	}
	if e = s.verifyManagerClosed(final, state, completed, h); e != nil {
		return time.Time{}, e
	}
	return completed, nil
}

func managerStateWithoutClose(state contracts.InitialBootstrapState) contracts.InitialBootstrapState {
	out := state
	m := *state.Manager
	out.Manager = &m
	m.Closing = nil
	m.RetiredAt = nil
	return out
}
func managerStateRetired(state contracts.InitialBootstrapState, at time.Time) contracts.InitialBootstrapState {
	out := state
	m := *state.Manager
	out.Manager = &m
	m.RetiredAt = &at
	return out
}
func (s *InitialSQLManager) managerCleanupDatabase(ctx context.Context, q initialManagerQuery, state contracts.InitialBootstrapState, effects bool) error {
	oid, start, now, e := s.database(ctx, q)
	if e != nil || oid != state.Manager.DatabaseOID || !start.Equal(state.Manager.PostmasterAt) {
		return cfg.ErrChanged
	}
	if effects && (now.Before(state.Manager.Closing.StartedAt) || !now.Before(state.Manager.Closing.Until)) {
		return cfg.ErrUnavailable
	}
	return nil
}
func checkManagerActivation(ctx context.Context, q initialManagerQuery, state contracts.InitialBootstrapState, want app.InitialInstallationObservation) error {
	var record, receipt []byte
	var at pgtype.Timestamptz
	var claim pgtype.UUID
	e := q.QueryRow(ctx, `SELECT record_json,audit_receipt_json,activated_at,claim_id FROM public.fleet_initial_activation WHERE installation_id=$1`, state.InstallationID).Scan(&record, &receipt, &at, &claim)
	if e != nil {
		return cfg.ErrUnavailable
	}
	observed, e := initialInstallationObservation(record, receipt, at, want.Record.Scope, want.Record.Claim.PlanDigest)
	if e != nil || observed.Disposition != app.InitialInstallationActivated || observed.Record.Claim.ID != uid(claim) || observed.Record.Claim.ID != want.Record.Claim.ID || !observed.ActivatedAt.Equal(want.ActivatedAt) || *observed.AuditReceipt != *want.AuditReceipt || !time.Now().Before(want.ValidUntil) || ctx.Err() != nil {
		return cfg.ErrChanged
	}
	return nil
}
func (s *InitialSQLManager) readManagerRetirement(ctx context.Context, state contracts.InitialBootstrapState) (time.Time, error) {
	var raw string
	e := s.pool.QueryRow(ctx, `SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE oid=$1 AND rolname=$2`, state.Manager.Receipt.OID, state.Manager.Receipt.Name).Scan(&raw)
	if e != nil {
		return time.Time{}, cfg.ErrChanged
	}
	var observed initialManagerProvenance
	if len(raw) > 2048 || !strictInitialHistoryJSON([]byte(raw), &observed) {
		return time.Time{}, cfg.ErrChanged
	}
	want := initialManagerRecord(state)
	// Original creation or the exact restrictive closing transaction is pending.
	if observed.RetiredAt == nil {
		if observed.Closing == nil {
			want.Closing = nil
		}
		a, _ := json.Marshal(observed)
		b, _ := json.Marshal(want)
		if string(a) != string(b) {
			return time.Time{}, cfg.ErrChanged
		}
		return time.Time{}, nil
	}
	at := *observed.RetiredAt
	if at.Before(state.Manager.Closing.StartedAt) || !at.Before(state.Manager.Closing.Until) {
		return time.Time{}, cfg.ErrChanged
	}
	want.RetiredAt = &at
	a, _ := json.Marshal(observed)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		return time.Time{}, cfg.ErrChanged
	}
	return at, nil
}
func managerSessionsAbsent(ctx context.Context, q initialManagerQuery, oid uint32) error {
	var absent bool
	e := q.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usesysid=$1)`, oid).Scan(&absent)
	if e != nil || !absent || ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	return nil
}
func (s *InitialSQLManager) terminateManagerSessions(ctx context.Context, state contracts.InitialBootstrapState) error {
	if _, e := s.checkRole(ctx, s.pool, state, true); e != nil {
		return e
	}
	if e := s.managerCleanupDatabase(ctx, s.pool, state, true); e != nil {
		return e
	}
	rows, e := s.pool.Query(ctx, `SELECT pid,backend_start FROM pg_stat_activity WHERE usesysid=$1 ORDER BY pid LIMIT 5`, state.Manager.Receipt.OID)
	if e != nil {
		return cfg.ErrUnavailable
	}
	type session struct {
		pid   int32
		start time.Time
	}
	sessions := []session{}
	for rows.Next() {
		var v session
		if rows.Scan(&v.pid, &v.start) != nil {
			rows.Close()
			return cfg.ErrUnavailable
		}
		sessions = append(sessions, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(sessions) > 4 {
		return cfg.ErrUnavailable
	}
	for _, v := range sessions {
		if _, e = s.checkRole(ctx, s.pool, state, true); e != nil {
			return e
		}
		if e = s.managerCleanupDatabase(ctx, s.pool, state, true); e != nil {
			return e
		}
		var stopped bool
		e = s.pool.QueryRow(ctx, `SELECT coalesce((SELECT pg_terminate_backend(pid,1000) FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2 AND usesysid=$3),true)`, v.pid, v.start, state.Manager.Receipt.OID).Scan(&stopped)
		if e != nil || !stopped {
			return cfg.ErrUnavailable
		}
		if _, e = s.checkRole(ctx, s.pool, state, true); e != nil {
			return e
		}
	}
	return managerSessionsAbsent(ctx, s.pool, state.Manager.Receipt.OID)
}
func (s *InitialSQLManager) verifyManagerClosed(ctx context.Context, state contracts.InitialBootstrapState, at time.Time, h app.InitialInstallationObservation) error {
	if e := s.managerCleanupDatabase(ctx, s.pool, state, false); e != nil {
		return e
	}
	retired := managerStateRetired(state, at)
	if _, e := s.checkRole(ctx, s.pool, retired, true); e != nil {
		return e
	}
	if e := checkInitialManagerGrants(ctx, s.pool, state.Manager.Receipt.OID, true); e != nil {
		return e
	}
	if e := verifyTransferredHistory(ctx, s.pool, state); e != nil {
		return e
	}
	if e := checkManagerActivation(ctx, s.pool, state, h); e != nil {
		return e
	}
	if e := managerSessionsAbsent(ctx, s.pool, state.Manager.Receipt.OID); e != nil {
		return e
	}
	if e := s.checkPassword(ctx, state, true); e != nil {
		return e
	}
	_, done, e := s.current(ctx, state)
	if e == nil {
		done()
	}
	return e
}
