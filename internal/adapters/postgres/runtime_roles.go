package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
)

// RuntimeRole is one compiled runtime login: its derived name, connection
// limit and exact grants. The inventory is fixed by this binary.
type RuntimeRole struct {
	Name        string
	Connections int
	grants      []publicRuntimeGrant
}

// RuntimeRoles is the complete compiled inventory of runtime logins for one
// installation: the public, configuration and owner-identity plans.
func RuntimeRoles(installation string) ([]RuntimeRole, error) {
	if !authorization.UUID(installation) {
		return nil, cfg.ErrInvalid
	}
	var out []RuntimeRole
	add := func(name string, named bool, connections int, limited bool, grants []publicRuntimeGrant, planned bool) error {
		if !named || !limited || !planned || connections < 1 {
			return cfg.ErrInvalid
		}
		out = append(out, RuntimeRole{Name: name, Connections: connections, grants: grants})
		return nil
	}
	for _, purpose := range contracts.PublicRuntimeRolePurposes() {
		name, named := PublicRuntimeRoleName(installation, purpose)
		limit, limited := contracts.PublicRuntimeRoleConnectionLimit(purpose)
		grants, planned := publicRuntimeRoleGrants(purpose)
		if err := add(name, named, limit, limited, grants, planned); err != nil {
			return nil, err
		}
	}
	for _, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		name, named := ConfigurationRuntimeRoleName(installation, purpose)
		grants, planned := configurationRuntimeRoleGrants(purpose)
		if err := add(name, named, contracts.ConfigurationRuntimeRoleConnections, true, grants, planned); err != nil {
			return nil, err
		}
	}
	for _, purpose := range contracts.OwnerIdentityRolePurposes() {
		name, named := OwnerIdentityRoleName(installation, purpose)
		grants, planned := ownerIdentityRoleGrants(purpose)
		if err := add(name, named, contracts.OwnerIdentityRoleConnections, true, grants, planned); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// RuntimeRoleReport lists what EnsureRuntimeRoles did, by role name.
type RuntimeRoleReport struct {
	Created, Updated, Missing []string
}

// runtimeRoleLockID serializes concurrent setup runs on role effects.
const runtimeRoleLockID int64 = 0x4153535652524f4c

// EnsureRuntimeRoles creates missing runtime logins, sets their attributes
// and passwords, and reconciles their privileges to the compiled grants. It
// never drops a role, so role OIDs stay stable. A role whose password is not
// in logins is reported as missing and left unchanged. The administrator must
// be a superuser or hold CREATEROLE with grant rights on the schema objects;
// for the bundled database it is the bundled superuser.
func EnsureRuntimeRoles(ctx context.Context, admin *pgx.ConnConfig, installation string, logins map[string]string) (RuntimeRoleReport, error) {
	var report RuntimeRoleReport
	if ctx == nil || ctx.Err() != nil || admin == nil || admin.TLSConfig == nil || admin.TLSConfig.InsecureSkipVerify || admin.TLSConfig.ServerName == "" || admin.TLSConfig.MinVersion < tls.VersionTLS13 || admin.User == "" || admin.Database == "" {
		return report, cfg.ErrInvalid
	}
	roles, err := RuntimeRoles(installation)
	if err != nil {
		return report, err
	}
	c := admin.Copy()
	c.RuntimeParams = map[string]string{"application_name": "asservat-setup-roles", "search_path": "pg_catalog,public", "timezone": "UTC", "lock_timeout": "30000ms", "statement_timeout": "60000ms", "idle_in_transaction_session_timeout": "60000ms", "synchronous_commit": "on", "row_security": "off"}
	c.ConnectTimeout = 5 * time.Second
	conn, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		return report, cfg.ErrUnavailable
	}
	defer func() {
		end, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = conn.Close(end)
	}()
	for _, role := range roles {
		password, ok := logins[role.Name]
		if !ok {
			report.Missing = append(report.Missing, role.Name)
			continue
		}
		created, err := ensureRuntimeRole(ctx, conn, role, password)
		if err != nil {
			return report, &RuntimeRoleError{Role: role.Name, Err: err}
		}
		if created {
			report.Created = append(report.Created, role.Name)
		} else {
			report.Updated = append(report.Updated, role.Name)
		}
	}
	return report, nil
}

// RuntimeRoleError names the role whose reconciliation failed.
type RuntimeRoleError struct {
	Role string
	Err  error
}

func (e *RuntimeRoleError) Error() string {
	return "runtime role " + e.Role + ": " + errorClassName(e.Err)
}
func (e *RuntimeRoleError) Unwrap() error { return e.Err }

func errorClassName(err error) string {
	switch {
	case errors.Is(err, cfg.ErrInvalid):
		return "invalid"
	case errors.Is(err, cfg.ErrChanged):
		return "grants differ from the compiled plan"
	case errors.Is(err, cfg.ErrDenied):
		return "denied"
	}
	return "unavailable"
}

func ensureRuntimeRole(ctx context.Context, conn *pgx.Conn, role RuntimeRole, password string) (bool, error) {
	verifier, err := sqlPasswordVerifier(SQLLogin{Username: role.Name, Password: password})
	if err != nil {
		return false, err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return false, cfg.ErrUnavailable
	}
	defer func() {
		end, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(end)
	}()
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", runtimeRoleLockID); err != nil {
		return false, cfg.ErrUnavailable
	}
	name := pgx.Identifier{role.Name}.Sanitize()
	attributes := " LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT " + strconv.Itoa(role.Connections) + " PASSWORD " + quoteSQLLiteral(verifier)
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", role.Name).Scan(&exists); err != nil {
		return false, cfg.ErrUnavailable
	}
	if exists {
		_, err = tx.Exec(ctx, "ALTER ROLE "+name+attributes)
	} else {
		_, err = tx.Exec(ctx, "CREATE ROLE "+name+attributes)
	}
	if err != nil {
		return false, cfg.ErrDenied
	}
	// Reconcile privileges: revoke everything in the schema, then grant the
	// compiled plan, inside one transaction. Revoking table privileges also
	// revokes column privileges.
	for _, statement := range []string{
		"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM " + name,
		"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM " + name,
		"REVOKE ALL ON ALL ROUTINES IN SCHEMA public FROM " + name,
		"REVOKE ALL ON SCHEMA public FROM " + name,
	} {
		if _, err = tx.Exec(ctx, statement); err != nil {
			return false, cfg.ErrDenied
		}
	}
	for _, g := range role.grants {
		if _, err = tx.Exec(ctx, g.sql(role.Name)); err != nil {
			return false, cfg.ErrDenied
		}
	}
	var oid uint32
	if err = tx.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", role.Name).Scan(&oid); err != nil {
		return false, cfg.ErrUnavailable
	}
	if err = runtimeRoleGrantsExact(ctx, tx, oid, role.grants); err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, cfg.ErrUnavailable
	}
	return !exists, nil
}

// runtimeRoleGrantsExact compares the role's actual privileges on tables,
// columns, schemas, databases and functions with the compiled grants.
func runtimeRoleGrantsExact(ctx context.Context, q publicRoleQuery, oid uint32, grants []publicRuntimeGrant) error {
	want := make([]string, 0, len(grants))
	functions := []string{}
	for _, g := range grants {
		if g.kind == "function" {
			functions = append(functions, "public."+g.object)
		} else {
			want = append(want, g.key())
		}
	}
	var resolved []string
	if err := q.QueryRow(ctx, `SELECT ARRAY(SELECT coalesce(to_regprocedure(x)::oid::text,'') FROM unnest($1::text[]) x)`, functions).Scan(&resolved); err != nil || len(resolved) != len(functions) {
		return cfg.ErrUnavailable
	}
	for _, object := range resolved {
		if object == "" {
			return cfg.ErrChanged
		}
		want = append(want, (publicRuntimeGrant{"function", object, "", "EXECUTE"}).key())
	}
	rows, err := q.Query(ctx, `SELECT 'table',n.nspname||'.'||c.relname,'',a.privilege_type FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'table',n.nspname||'.'||c.relname,x.attname,a.privilege_type FROM pg_attribute x JOIN pg_class c ON c.oid=x.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(x.attacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'schema',nspname,'',a.privilege_type FROM pg_namespace CROSS JOIN LATERAL aclexplode(nspacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'database',datname,'',a.privilege_type FROM pg_database CROSS JOIN LATERAL aclexplode(datacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'function',n.nspname||'.'||p.oid::text,'',a.privilege_type FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE a.grantee=$1`, oid)
	if err != nil {
		return cfg.ErrUnavailable
	}
	defer rows.Close()
	actual := []string{}
	for rows.Next() {
		var g publicRuntimeGrant
		if err = rows.Scan(&g.kind, &g.object, &g.column, &g.privilege); err != nil {
			return cfg.ErrUnavailable
		}
		if g.kind == "table" || g.kind == "function" {
			if !strings.HasPrefix(g.object, "public.") {
				return cfg.ErrChanged
			}
			g.object = strings.TrimPrefix(g.object, "public.")
		}
		actual = append(actual, g.key())
	}
	if rows.Err() != nil {
		return cfg.ErrUnavailable
	}
	slices.Sort(actual)
	slices.Sort(want)
	if !slices.Equal(actual, slices.Compact(want)) {
		return cfg.ErrChanged
	}
	return nil
}
