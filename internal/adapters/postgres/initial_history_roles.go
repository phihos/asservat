package postgres

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InitialSQLHistoryRoleName is distinct from all temporary activation roles.
// This installation-owned passive login never enters the activation Pod.
func InitialSQLHistoryRoleName(installation string) (string, error) {
	if !authorization.UUID(installation) {
		return "", value.ErrInvalid
	}
	return initialRoleName(installation, "history"), nil
}
func ValidInitialSQLHistoryLogin(installation string, login InitialSQLLogin) bool {
	if !authorization.UUID(installation) || login.Username != initialRoleName(installation, "history") {
		return false
	}
	raw, e := base64.RawURLEncoding.DecodeString(login.Password)
	defer clear(raw)
	return e == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == login.Password
}
func initialHistoryGrants() []initialRoleGrant {
	return []initialRoleGrant{{"schema", "public", "", "USAGE"}, {"table", "goose_db_version", "", "SELECT"}, {"table", "fleet_initial_activation", "", "SELECT"}}
}

// ProvisionHistory uses the original protected bootstrap password. Existing
// role/password/ACL state must match exactly; no ALTER/reset or password retry
// can adopt a previously issued unknown login. New creation is possible only
// while the separately guarded original setup interval and pristine DB hold.
func (s *InitialSQLRoles) ProvisionHistory(ctx context.Context, p InitialSQLCredentials, login InitialSQLLogin, manager contracts.InitialSQLHistoryManager) (err error) {
	phase := "inputs"
	sqlState := ""
	defer func() {
		if err != nil {
			err = initialSQLHistoryFailure{phase: phase, sqlState: sqlState, expired: ctx != nil && ctx.Err() != nil, cause: err}
		}
	}()
	sqlFailure := func(e error) error { sqlState = initialHistorySQLState(e); return value.ErrUnavailable }

	if s == nil || !validInitialHistoryManager(manager) || !ValidInitialSQLHistoryLogin(s.installation, login) {
		return value.ErrInvalid
	}
	for _, existing := range p.logins() {
		if existing.Password == login.Password {
			return value.ErrInvalid
		}
	}
	phase = "password-verifier"
	verifier, e := initialPasswordVerifier(login)
	if e != nil {
		return e
	}
	phase = "transaction"
	e = s.transaction(ctx, p, func(ctx context.Context, tx pgx.Tx) error {
		phase = "original-interval"
		if e := initialRolesCurrent(ctx, tx, p); e != nil {
			return e
		}
		phase = "creator-identity"
		if e := checkInitialHistoryCreator(ctx, tx, manager); e != nil {
			return e
		}
		phase = "original-roles"
		if e := s.verify(ctx, tx, p, false); e != nil {
			return e
		}
		phase = "history-role-lookup"
		var exists bool
		if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", login.Username).Scan(&exists); e != nil {
			return sqlFailure(e)
		}
		if !exists {
			phase = "pristine-history"
			for _, name := range initialInstallationTables {
				if name == "goose_db_version" {
					continue
				}
				query := "SELECT EXISTS(SELECT 1 FROM " + pgx.Identifier{"public", name}.Sanitize() + ")"
				args := []any{}
				if name == "fleet_trust" {
					query = "SELECT EXISTS(SELECT 1 FROM public.fleet_trust WHERE installation_id<>$1 OR NOT suspended OR NOT recovery_blocked OR activated_postmaster_at IS NOT NULL OR activated_database_oid IS NOT NULL)"
					args = append(args, p.InstallationID)
				}
				var used bool
				if e := tx.QueryRow(ctx, query, args...).Scan(&used); e != nil || used {
					return value.ErrDenied
				}
			}
			phase = "history-role-create"
			if _, e := tx.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login.Username}.Sanitize()+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4 PASSWORD '"+verifier+"'"); e != nil {
				return sqlFailure(e)
			}
			phase = "history-role-grants"
			for _, g := range initialHistoryGrants() {
				if _, e := tx.Exec(ctx, g.sql("GRANT", login.Username)); e != nil {
					return sqlFailure(e)
				}
			}
			// PostgreSQL grants the original non-superuser creator ADMIN through
			// its bootstrap superuser. That creator cannot revoke this grant.
			// Verify only the independently pinned original manager below.
		}
		phase = "history-role-privileges"
		if e := verifyInitialHistoryRole(ctx, tx, login.Username, manager); e != nil {
			return e
		}
		phase = "creator-identity"
		if e := checkInitialHistoryCreator(ctx, tx, manager); e != nil {
			return e
		}
		phase = "final-original-interval"
		return initialRolesCurrent(ctx, tx, p)
	})
	if e != nil {
		return e
	}
	phase = "password-authentication"
	check, end := context.WithDeadline(ctx, p.NotAfter)
	defer end()
	check, done := context.WithTimeout(check, 5*time.Second)
	defer done()
	c := s.pool.Config().ConnConfig.Copy()
	c.User, c.Password, c.RequireAuth = login.Username, login.Password, "scram-sha-256"
	c.ValidateConnect, c.AfterConnect = nil, nil
	conn, e := pgx.ConnectConfig(check, c)
	if e != nil {
		return value.ErrDenied
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(check), time.Second)
		defer stop()
		_ = conn.Close(cleanup)
	}()
	phase = "password-ping"
	if e = conn.Ping(check); e != nil || check.Err() != nil {
		return sqlFailure(e)
	}
	return nil
}

type initialHistoryQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func verifyInitialHistoryRole(ctx context.Context, q initialHistoryQuery, username string, manager contracts.InitialSQLHistoryManager) error {
	if !validInitialHistoryManager(manager) {
		return value.ErrInvalid
	}
	var oid uint32
	var flags bool
	e := q.QueryRow(ctx, `SELECT oid,NOT rolsuper AND NOT rolinherit AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolconnlimit=4 AND rolcanlogin AND rolvaliduntil IS NULL FROM pg_roles WHERE rolname=$1`, username).Scan(&oid, &flags)
	if e != nil || !flags {
		return value.ErrDenied
	}
	// The history login has no outgoing membership. Its only incoming grant
	// is the original, independently pinned trusted manager, with exact options.
	var unsafe bool
	e = q.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_roles WHERE oid=$2 AND rolname=$3 AND NOT rolsuper)
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE oid=10 AND rolsuper)
 OR (SELECT count(*) FROM pg_auth_members WHERE roleid=$1)<>1
 OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=$1 OR (roleid=$1 AND NOT(member=$2 AND grantor=10 AND admin_option AND NOT inherit_option AND NOT set_option)))
 OR EXISTS(SELECT 1 FROM pg_class WHERE relowner=$1) OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspowner=$1)
 OR EXISTS(SELECT 1 FROM pg_database WHERE datdba=$1) OR EXISTS(SELECT 1 FROM pg_proc WHERE proowner=$1)
 OR EXISTS(SELECT 1 FROM pg_db_role_setting WHERE setrole=$1)
 OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema') AND has_function_privilege($1::oid,p.oid,'EXECUTE'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee=0 AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')
 OR EXISTS(SELECT 1 FROM pg_attribute x JOIN pg_class c ON c.oid=x.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(x.attacl) a WHERE a.grantee=0 AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')
 OR EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE a.grantee=0 AND a.privilege_type='CREATE')
 OR EXISTS(SELECT 1 FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a WHERE a.grantee=0 AND a.privilege_type='CREATE')`, oid, manager.OID, manager.Name).Scan(&unsafe)
	if e != nil || unsafe {
		return value.ErrDenied
	}
	rows, e := q.Query(ctx, `SELECT 'table',n.nspname||'.'||c.relname,'',a.privilege_type,a.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'table',n.nspname||'.'||c.relname,x.attname,a.privilege_type,a.is_grantable FROM pg_attribute x JOIN pg_class c ON c.oid=x.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(x.attacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'schema',nspname,'',a.privilege_type,a.is_grantable FROM pg_namespace CROSS JOIN LATERAL aclexplode(nspacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'database',datname,'',a.privilege_type,a.is_grantable FROM pg_database CROSS JOIN LATERAL aclexplode(datacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'function',proname,'',a.privilege_type,a.is_grantable FROM pg_proc CROSS JOIN LATERAL aclexplode(proacl) a WHERE a.grantee=$1`, oid)
	if e != nil {
		return value.ErrUnavailable
	}
	defer rows.Close()
	actual := []string{}
	for rows.Next() {
		var g initialRoleGrant
		var grantable bool
		if e = rows.Scan(&g.kind, &g.object, &g.column, &g.privilege, &grantable); e != nil || grantable {
			return value.ErrDenied
		}
		if g.kind == "table" {
			if !strings.HasPrefix(g.object, "public.") {
				return value.ErrDenied
			}
			g.object = strings.TrimPrefix(g.object, "public.")
		}
		actual = append(actual, g.key())
	}
	if rows.Err() != nil {
		return value.ErrUnavailable
	}
	want := []string{}
	for _, g := range initialHistoryGrants() {
		want = append(want, g.key())
	}
	slices.Sort(want)
	slices.Sort(actual)
	if !slices.Equal(want, actual) {
		return value.ErrDenied
	}
	return nil
}

// CheckInitialSQLHistoryRole is read-only and uses the supplied history pool's
// actual login. It never opens a maintenance connection or repairs permissions.
// Callers still need current native bootstrap authority for every history read.
func CheckInitialSQLHistoryRole(ctx context.Context, pool *pgxpool.Pool, installation string, manager contracts.InitialSQLHistoryManager) error {
	name, e := InitialSQLHistoryRoleName(installation)
	if e != nil || ctx == nil || pool == nil || !validInitialHistoryManager(manager) {
		return value.ErrInvalid
	}
	c := pool.Config()
	tlsConfig := c.ConnConfig.TLSConfig
	if c.ConnConfig.User != name || c.MaxConns > 4 || tlsConfig == nil || tlsConfig.InsecureSkipVerify || tlsConfig.ServerName == "" || tlsConfig.MinVersion < tls.VersionTLS13 || len(c.ConnConfig.Fallbacks) != 0 || c.ConnConfig.Tracer != nil {
		return value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var user string
	if e = pool.QueryRow(ctx, "SELECT current_user").Scan(&user); e != nil || user != name {
		return value.ErrDenied
	}
	if e = verifyInitialHistoryRole(ctx, pool, name, manager); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return value.ErrUnavailable
	}
	return nil
}

func validInitialHistoryManager(manager contracts.InitialSQLHistoryManager) bool {
	return manager.OID != 0 && manager.OID != 10 && identity.Text(manager.Name, 63)
}

// Current maintenance identity must match the independently supplied plan pin.
// The passive verifier does not require this administrator to retain LOGIN or
// CREATEROLE after setup, but cannot accept a renamed or replaced identity.
func checkInitialHistoryCreator(ctx context.Context, q initialHistoryQuery, manager contracts.InitialSQLHistoryManager) error {
	var current bool
	if !validInitialHistoryManager(manager) {
		return value.ErrInvalid
	}
	e := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolname=$1 AND oid=$2 AND NOT rolsuper AND rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)`, manager.Name, manager.OID).Scan(&current)
	if e != nil {
		return value.ErrUnavailable
	}
	if !current {
		return value.ErrDenied
	}
	return nil
}

// CheckHistoryManager rejects an inconsistent protected manager pin before the
// supervisor begins preparation. This read does not qualify a later effect;
// ProvisionHistory repeats the check under its original transaction interval.
func (s *InitialSQLRoles) CheckHistoryManager(ctx context.Context, manager contracts.InitialSQLHistoryManager) error {
	if s == nil || ctx == nil || s.pool == nil || !validInitialHistoryManager(manager) {
		return value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	if e := checkInitialHistoryCreator(ctx, s.pool, manager); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return value.ErrUnavailable
	}
	return nil
}
