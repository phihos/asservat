package postgres

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InitialSQLManagerRoot is the producer's concrete protected Kubernetes seed,
// not an HTTP input. Only its acknowledged first claim can start role creation.
// Reopening the same seed is lookup-only, even if no SQL role can be found.
type InitialSQLManagerRoot interface {
	ClaimBootstrapSQLManager(context.Context, uint32, time.Time) (contracts.InitialBootstrapState, bool, time.Time, error)
	ReadBootstrapSQLManager(context.Context) (contracts.InitialBootstrapState, time.Time, error)
	CompleteBootstrapSQLManager(context.Context, contracts.InitialBootstrapState, time.Time, contracts.InitialSQLHistoryManager) error
}

// InitialSQLManager owns a separately supplied trusted SQL administrator pool.
// It never enters initial-prepare, activation or runtime processes. Close joins
// all admitted work before returning; an expired or uncertain claim is not reset.
type InitialSQLManager struct {
	pool         *pgxpool.Pool
	root         InitialSQLManagerRoot
	lifetime     context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	closed, busy bool
	joined       sync.WaitGroup
	adminOID     uint32
}

func NewInitialSQLManager(ctx context.Context, c *pgx.ConnConfig, root InitialSQLManagerRoot) (*InitialSQLManager, error) {
	if ctx == nil || ctx.Err() != nil || c == nil || root == nil || c.User == "" || c.Database == "" || c.TLSConfig == nil || c.TLSConfig.InsecureSkipVerify || c.TLSConfig.ServerName == "" || c.TLSConfig.MinVersion < tls.VersionTLS13 || len(c.Fallbacks) != 0 || c.Tracer != nil || c.ValidateConnect != nil || c.AfterConnect != nil {
		return nil, cfg.ErrInvalid
	}
	c = c.Copy()
	c.RuntimeParams = map[string]string{"application_name": "asservat-initial-bootstrap", "search_path": "pg_catalog,public", "timezone": "UTC", "lock_timeout": "1000ms", "statement_timeout": "5000ms", "idle_in_transaction_session_timeout": "5000ms", "synchronous_commit": "on", "row_security": "off"}
	c.ConnectTimeout = 5 * time.Second
	p, e := pgxpool.ParseConfig("")
	if e != nil {
		return nil, cfg.ErrInvalid
	}
	p.ConnConfig, p.MaxConns, p.MinConns = c, 2, 0
	p.BeforeConnect, p.AfterConnect, p.BeforeAcquire, p.AfterRelease = nil, nil, nil, nil
	lifetime, cancel := context.WithCancel(ctx)
	pool, e := pgxpool.NewWithConfig(lifetime, p)
	if e != nil {
		cancel()
		return nil, cfg.ErrUnavailable
	}
	s := &InitialSQLManager{pool: pool, root: root, lifetime: lifetime, cancel: cancel}
	bounded, end := context.WithTimeout(lifetime, 5*time.Second)
	defer end()
	// This is explicit initial administration, never a runtime privilege. The
	// separate original manager is always a nonsuperuser with bounded attributes.
	var qualified bool
	e = pool.QueryRow(bounded, `SELECT oid,rolsuper AND rolcanlogin AND NOT pg_is_in_recovery() FROM pg_roles WHERE rolname=current_user`).Scan(&s.adminOID, &qualified)
	if e != nil || !qualified || bounded.Err() != nil {
		s.Close()
		return nil, cfg.ErrUnavailable
	}
	return s, nil
}

func (s *InitialSQLManager) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.joined.Wait()
	s.pool.Close()
}
func (s *InitialSQLManager) enter(ctx context.Context) (context.Context, func(), error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, cfg.ErrUnavailable
	}
	s.mu.Lock()
	if s.closed || s.busy || s.lifetime.Err() != nil {
		s.mu.Unlock()
		return nil, nil, cfg.ErrUnavailable
	}
	s.busy = true
	s.joined.Add(1)
	s.mu.Unlock()
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	stop := context.AfterFunc(s.lifetime, cancel)
	return bounded, func() {
		stop()
		cancel()
		s.mu.Lock()
		s.busy = false
		s.mu.Unlock()
		s.joined.Done()
	}, nil
}

type initialManagerProvenance struct {
	Format         string                           `json:"format"`
	InstallationID string                           `json:"installationID"`
	RequestID      string                           `json:"requestID"`
	SeedUID        string                           `json:"seedUID"`
	ClusterID      string                           `json:"clusterID"`
	IssuerEpoch    string                           `json:"issuerEpoch"`
	OperationID    string                           `json:"operationID"`
	DatabaseOID    uint32                           `json:"databaseOID"`
	PostmasterAt   time.Time                        `json:"postmasterAt"`
	Until          time.Time                        `json:"until"`
	Closing        *contracts.InitialBootstrapClose `json:"closing,omitempty"`
	RetiredAt      *time.Time                       `json:"retiredAt,omitempty"`
}

func initialManagerName(s contracts.InitialBootstrapState) string {
	return initialRoleName(s.InstallationID, "manager")
}
func initialManagerRecord(s contracts.InitialBootstrapState) initialManagerProvenance {
	m := s.Manager
	return initialManagerProvenance{Format: "asservat-initial-manager/v1", InstallationID: s.InstallationID, RequestID: s.RequestID, SeedUID: s.SeedUID, ClusterID: s.ClusterID, IssuerEpoch: s.IssuerEpoch, OperationID: m.OperationID, DatabaseOID: m.DatabaseOID, PostmasterAt: m.PostmasterAt, Until: m.Until, Closing: m.Closing, RetiredAt: m.RetiredAt}
}
func initialManagerState(s contracts.InitialBootstrapState) bool {
	m := s.Manager
	if s.Format != contracts.InitialBootstrapStateFormat || !authorization.UUID(s.InstallationID) || !authorization.UUID(s.RequestID) || !authorization.UUID(s.SeedUID) || !authorization.UUID(s.ClusterID) || !authorization.UUID(s.IssuerEpoch) || m == nil || !authorization.UUID(m.OperationID) || m.DatabaseOID == 0 || m.PostmasterAt.Year() < 2020 || m.StartedAt.Year() < 2020 || m.Until.Sub(m.StartedAt) != 30*time.Minute || !m.StartedAt.Equal(m.StartedAt.Truncate(time.Microsecond)) {
		return false
	}
	if m.Receipt != nil && (m.Receipt.Name != initialManagerName(s) || m.Receipt.OID == 0 || m.Receipt.OID == 10) {
		return false
	}
	if c := m.Closing; c != nil {
		if m.Receipt == nil || !authorization.UUID(c.OperationID) || c.StartedAt.Before(m.StartedAt) || c.Until.Sub(c.StartedAt) != 30*time.Second || !c.StartedAt.Equal(c.StartedAt.Truncate(time.Microsecond)) {
			return false
		}
	}
	if m.RetiredAt != nil && (m.Closing == nil || m.RetiredAt.Before(m.Closing.StartedAt) || !m.RetiredAt.Before(m.Closing.Until)) {
		return false
	}
	return true
}
func initialManagerEqual(a, b contracts.InitialBootstrapState) bool {
	if !initialManagerState(a) || !initialManagerState(b) {
		return false
	}
	x, _ := json.Marshal(initialManagerRecord(a))
	y, _ := json.Marshal(initialManagerRecord(b))
	if (a.Manager.Receipt == nil) != (b.Manager.Receipt == nil) || a.Manager.Receipt != nil && *a.Manager.Receipt != *b.Manager.Receipt {
		return false
	}
	return bytes.Equal(x, y) && a.Passwords.Manager == b.Passwords.Manager && a.Retired == b.Retired
}

type initialManagerQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (s *InitialSQLManager) database(ctx context.Context, q initialManagerQuery) (uint32, time.Time, time.Time, error) {
	var oid, admin uint32
	var start, now time.Time
	var valid bool
	e := q.QueryRow(ctx, `SELECT (SELECT oid FROM pg_database WHERE datname=current_database()), pg_postmaster_start_time(), clock_timestamp(), oid, rolsuper AND rolcanlogin AND NOT pg_is_in_recovery() FROM pg_roles WHERE rolname=current_user`).Scan(&oid, &start, &now, &admin, &valid)
	if e != nil || !valid || admin != s.adminOID || ctx.Err() != nil {
		return 0, time.Time{}, time.Time{}, cfg.ErrUnavailable
	}
	return oid, start.UTC(), now.UTC(), nil
}
func (s *InitialSQLManager) current(ctx context.Context, state contracts.InitialBootstrapState) (context.Context, context.CancelFunc, error) {
	current, until, e := s.root.ReadBootstrapSQLManager(ctx)
	if e != nil || !initialManagerEqual(current, state) || !time.Now().Before(until) || ctx.Err() != nil {
		return nil, nil, cfg.ErrChanged
	}
	bounded, end := context.WithDeadline(ctx, until)
	if bounded.Err() != nil {
		end()
		return nil, nil, cfg.ErrUnavailable
	}
	return bounded, end, nil
}

func (s *InitialSQLManager) transaction(ctx context.Context, state contracts.InitialBootstrapState, f func(context.Context, pgx.Tx) error) error {
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return cfg.ErrUnavailable
	}
	defer func() {
		cleanup, end := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer end()
		_ = tx.Rollback(cleanup)
	}()
	if _, e = tx.Exec(ctx, `SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'; SET LOCAL idle_in_transaction_session_timeout='5s'; SET LOCAL synchronous_commit=on; SET LOCAL row_security=off`); e != nil {
		return cfg.ErrUnavailable
	}
	// Fixed namespace plus original installation; collision can only deny work.
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1095979853,hashtext($1))`, state.InstallationID); e != nil {
		return cfg.ErrUnavailable
	}
	if e = f(ctx, tx); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	if e = tx.Commit(ctx); e != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

// Provision obtains Fresh directly from the protected seed. Only that one
// acknowledged call can CREATE. An unknown SQL commit is never retried; next
// invocation checks the exact original role, password and provenance instead.
func (s *InitialSQLManager) Provision(ctx context.Context) (contracts.InitialSQLHistoryManager, error) {
	var zero contracts.InitialSQLHistoryManager
	bounded, end, e := s.enter(ctx)
	if e != nil {
		return zero, e
	}
	defer end()
	oid, started, _, e := s.database(bounded, s.pool)
	if e != nil {
		return zero, e
	}
	state, fresh, until, e := s.root.ClaimBootstrapSQLManager(bounded, oid, started)
	if e != nil || !initialManagerState(state) || state.Manager.Closing != nil || state.Retired || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	bounded, stop := context.WithDeadline(bounded, until)
	defer stop()
	bounded, stop = s.capManager(bounded, state)
	defer stop()
	bounded, stop, e = s.current(bounded, state)
	if e != nil {
		return zero, e
	}
	defer stop()
	login := InitialSQLLogin{Username: initialManagerName(state), Password: state.Passwords.Manager}
	verifier := ""
	if fresh {
		verifier, e = initialPasswordVerifier(login)
		if e != nil {
			return zero, cfg.ErrInvalid
		}
	}
	var pin contracts.InitialSQLHistoryManager
	e = s.transaction(bounded, state, func(ctx context.Context, tx pgx.Tx) error {
		if e = s.activeDatabase(ctx, tx, state); e != nil {
			return e
		}
		var exists bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, login.Username).Scan(&exists); e != nil {
			return cfg.ErrUnavailable
		}
		if !exists {
			if !fresh || state.Manager.Receipt != nil {
				return cfg.ErrChanged
			}
			ddl := "CREATE ROLE " + pgx.Identifier{login.Username}.Sanitize() + " LOGIN NOINHERIT NOSUPERUSER NOCREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4 VALID UNTIL '" + state.Manager.Until.Format(time.RFC3339Nano) + "' PASSWORD '" + verifier + "'"
			if _, e = tx.Exec(ctx, ddl); e != nil {
				return cfg.ErrUnavailable
			}
			if e = writeInitialManagerComment(ctx, tx, login.Username, initialManagerRecord(state)); e != nil {
				return e
			}
		}
		pin, e = s.checkRole(ctx, tx, state, false)
		if e != nil {
			return e
		}
		if e = checkInitialManagerGrants(ctx, tx, pin.OID, false); e != nil {
			return e
		}
		return s.activeDatabase(ctx, tx, state)
	})
	if e != nil {
		return zero, e
	}
	pinned := state
	m := *state.Manager
	pinned.Manager = &m
	m.Receipt = &pin
	if e = s.checkPassword(bounded, pinned, false); e != nil {
		return zero, e
	}
	final, done, e := s.current(bounded, state)
	if e != nil {
		return zero, e
	}
	defer done()
	if e = s.root.CompleteBootstrapSQLManager(final, state, until, pin); e != nil || final.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	return pin, nil
}
func (s *InitialSQLManager) capManager(ctx context.Context, state contracts.InitialBootstrapState) (context.Context, context.CancelFunc) {
	return context.WithDeadline(ctx, state.Manager.Until)
}
func (s *InitialSQLManager) activeDatabase(ctx context.Context, q initialManagerQuery, state contracts.InitialBootstrapState) error {
	oid, start, now, e := s.database(ctx, q)
	if e != nil || oid != state.Manager.DatabaseOID || !start.Equal(state.Manager.PostmasterAt) || now.Before(state.Manager.StartedAt) || !now.Before(state.Manager.Until) {
		return cfg.ErrChanged
	}
	return nil
}

func writeInitialManagerComment(ctx context.Context, tx pgx.Tx, name string, v initialManagerProvenance) error {
	b, e := json.Marshal(v)
	if e != nil || len(b) > 2048 {
		return cfg.ErrInvalid
	}
	_, e = tx.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{name}.Sanitize()+" IS '"+strings.ReplaceAll(string(b), "'", "''")+"'")
	if e != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

func (s *InitialSQLManager) checkRole(ctx context.Context, q initialManagerQuery, state contracts.InitialBootstrapState, retired bool) (contracts.InitialSQLHistoryManager, error) {
	var zero contracts.InitialSQLHistoryManager
	var oid uint32
	var flags bool
	var expiry pgtype.Timestamptz
	var comment string
	e := q.QueryRow(ctx, `SELECT oid,NOT rolsuper AND NOT rolinherit AND NOT rolcreatedb AND rolcreaterole=$2 AND NOT rolreplication AND NOT rolbypassrls AND rolconnlimit=4 AND rolcanlogin=$2 AND (NOT $3 OR rolpassword IS NULL),rolvaliduntil,coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_authid WHERE rolname=$1`, initialManagerName(state), !retired, retired).Scan(&oid, &flags, &expiry, &comment)
	if e != nil || !flags || oid == s.adminOID || !expiry.Valid || !expiry.Time.Equal(state.Manager.Until) || state.Manager.Receipt != nil && state.Manager.Receipt.OID != oid {
		return zero, cfg.ErrChanged
	}
	var record initialManagerProvenance
	if len(comment) > 2048 || !strictInitialHistoryJSON([]byte(comment), &record) {
		return zero, cfg.ErrChanged
	}
	b, _ := json.Marshal(initialManagerRecord(state))
	actual, _ := json.Marshal(record)
	if !bytes.Equal(b, actual) {
		return zero, cfg.ErrChanged
	}
	var unsafe bool
	// Initial superuser CREATE adds no creator membership. Later manager-created
	// children have the exact unavoidable ADMIN-only provenance, never SET/INHERIT.
	e = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=$1 OR (member=$1 AND (grantor<>10 OR NOT admin_option OR inherit_option OR set_option OR NOT EXISTS(SELECT 1 FROM pg_roles child WHERE child.oid=roleid AND child.rolname=ANY($2::text[]))))) OR EXISTS(SELECT 1 FROM pg_class WHERE relowner=$1) OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspowner=$1) OR EXISTS(SELECT 1 FROM pg_database WHERE datdba=$1) OR EXISTS(SELECT 1 FROM pg_proc WHERE proowner=$1) OR EXISTS(SELECT 1 FROM pg_db_role_setting WHERE setrole=$1)`, oid, []string{initialRoleName(state.InstallationID, "prepare"), initialRoleName(state.InstallationID, "audit"), initialRoleName(state.InstallationID, "activate"), initialRoleName(state.InstallationID, "history")}).Scan(&unsafe)
	if e != nil || unsafe || ctx.Err() != nil {
		return zero, cfg.ErrChanged
	}
	return contracts.InitialSQLHistoryManager{Name: initialManagerName(state), OID: oid}, nil
}

func (s *InitialSQLManager) checkPassword(ctx context.Context, state contracts.InitialBootstrapState, denied bool) error {
	c := s.pool.Config().ConnConfig.Copy()
	c.User, c.Password, c.RequireAuth = initialManagerName(state), state.Passwords.Manager, "scram-sha-256"
	c.ValidateConnect, c.AfterConnect = nil, nil
	conn, e := pgx.ConnectConfig(ctx, c)
	if e != nil {
		var pg *pgconn.PgError
		if denied && errors.As(e, &pg) && (pg.Code == "28000" || pg.Code == "28P01") && ctx.Err() == nil {
			return nil
		}
		return cfg.ErrUnavailable
	}
	defer func() {
		cleanup, end := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer end()
		_ = conn.Close(cleanup)
	}()
	if denied {
		return cfg.ErrChanged
	}
	var oid uint32
	if e = conn.QueryRow(ctx, `SELECT oid FROM pg_roles WHERE rolname=current_user`).Scan(&oid); e != nil || state.Manager.Receipt != nil && state.Manager.Receipt.OID != oid || ctx.Err() != nil {
		return cfg.ErrChanged
	}
	return nil
}
