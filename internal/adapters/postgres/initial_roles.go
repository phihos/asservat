package postgres

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xdg-go/scram"
)

// InitialSQLCredentials is secret provisioning state, never an audit or public
// startup record. Persist it once in protected installation storage before any
// role creation. Missing state is not permission to generate replacement roles.
type InitialSQLCredentials struct {
	InstallationID                 string
	NotBefore, NotAfter            time.Time
	Preparation, Audit, Activation InitialSQLLogin
}
type InitialSQLLogin struct{ Username, Password string }

func NewInitialSQLCredentials(installation string, now time.Time) (InitialSQLCredentials, error) {
	if !authorization.UUID(installation) || now.Year() < 2020 || now.Year() > 9998 {
		return InitialSQLCredentials{}, value.ErrInvalid
	}
	now = now.UTC().Truncate(time.Second)
	p := InitialSQLCredentials{InstallationID: installation, NotBefore: now, NotAfter: now.Add(15 * time.Minute)}
	for role, login := range map[string]*InitialSQLLogin{"prepare": &p.Preparation, "audit": &p.Audit, "activate": &p.Activation} {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return InitialSQLCredentials{}, value.ErrUnavailable
		}
		login.Username = initialRoleName(installation, role)
		login.Password = base64.RawURLEncoding.EncodeToString(b)
		clear(b)
	}
	return p, nil
}
func initialRoleName(installation, role string) string {
	return "asservat_init_" + strings.ReplaceAll(installation, "-", "") + "_" + role
}

// InitialSQLRoleName binds the private executable's projected credentials to
// this installation and facet before it opens a database connection.
func InitialSQLRoleName(installation, role string) (string, error) {
	if !authorization.UUID(installation) {
		return "", value.ErrInvalid
	}
	switch role {
	case "prepare", "audit", "activate":
		return initialRoleName(installation, role), nil
	default:
		return "", value.ErrInvalid
	}
}
func (p InitialSQLCredentials) logins() []InitialSQLLogin {
	return []InitialSQLLogin{p.Preparation, p.Audit, p.Activation}
}
func (p InitialSQLCredentials) valid() bool {
	if !authorization.UUID(p.InstallationID) || p.NotBefore.Year() < 2020 || p.NotAfter.Sub(p.NotBefore) != 15*time.Minute || !p.NotBefore.Equal(p.NotBefore.Truncate(time.Second)) {
		return false
	}
	seen := map[string]bool{}
	for i, l := range p.logins() {
		b, err := base64.RawURLEncoding.DecodeString(l.Password)
		valid := err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == l.Password
		clear(b)
		if !valid || seen[l.Password] || l.Username != initialRoleName(p.InstallationID, []string{"prepare", "audit", "activate"}[i]) {
			return false
		}
		seen[l.Password] = true
	}
	return true
}

// Use the maintained SCRAM implementation, not hand-written password crypto.
// Only its salted verifier reaches role DDL; plaintext passwords are never SQL
// statements or bind parameters. Hashes and credentials remain sensitive.
func initialPasswordVerifier(l InitialSQLLogin) (string, error) {
	if len(l.Password) != 43 {
		return "", value.ErrInvalid
	}
	password, err := base64.RawURLEncoding.DecodeString(l.Password)
	valid := err == nil && len(password) == 32 && base64.RawURLEncoding.EncodeToString(password) == l.Password
	clear(password)
	if !valid {
		return "", value.ErrInvalid
	}
	c, err := scram.SHA256.NewClient(l.Username, l.Password, "")
	if err != nil {
		return "", value.ErrInvalid
	}
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return "", value.ErrUnavailable
	}
	defer clear(salt)
	stored, err := c.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(salt), Iters: 4096})
	if err != nil {
		return "", value.ErrUnavailable
	}
	defer clear(stored.StoredKey)
	defer clear(stored.ServerKey)
	b64 := base64.StdEncoding.EncodeToString
	return "SCRAM-SHA-256$4096:" + b64(salt) + "$" + b64(stored.StoredKey) + ":" + b64(stored.ServerKey), nil
}

type InitialSQLRoles struct {
	pool         *pgxpool.Pool
	installation string
}

// This maintenance facet deliberately does not use the ordinary runtime
// Ledger constructor: CREATEROLE belongs only to trusted installation. The
// principal must be non-superuser, with separately delegated grant options.
func NewInitialSQLRoles(ctx context.Context, pool *pgxpool.Pool, installation string) (*InitialSQLRoles, error) {
	if ctx == nil || pool == nil || !authorization.UUID(installation) {
		return nil, value.ErrInvalid
	}
	c := pool.Config()
	t := c.ConnConfig.TLSConfig
	if c.MaxConns > 4 || t == nil || t.InsecureSkipVerify || t.ServerName == "" || t.MinVersion < tls.VersionTLS13 || len(c.ConnConfig.Fallbacks) != 0 || c.ConnConfig.Tracer != nil {
		return nil, value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var qualified bool
	err := pool.QueryRow(ctx, `SELECT NOT rolsuper AND rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND NOT pg_is_in_recovery() FROM pg_roles WHERE rolname=current_user`).Scan(&qualified)
	if err != nil || !qualified {
		return nil, value.ErrDenied
	}
	return &InitialSQLRoles{pool, installation}, nil
}

type initialRoleGrant struct{ kind, object, column, privilege string }

func initialRoleGrants(role int) []initialRoleGrant {
	out := []initialRoleGrant{{"schema", "public", "", "USAGE"}}
	add := func(table, privilege string, columns ...string) {
		if len(columns) == 0 {
			out = append(out, initialRoleGrant{"table", table, "", privilege})
			return
		}
		for _, c := range columns {
			out = append(out, initialRoleGrant{"table", table, c, privilege})
		}
	}
	if role == 0 || role == 2 {
		for _, name := range initialInstallationTables {
			add(name, "SELECT")
			add(name, "MAINTAIN")
		}
	}
	switch role {
	case 0:
		add("fleet_initial_activation", "INSERT")
		add("fleet_initial_activation", "UPDATE", "singleton")
		add("fleet_trust", "INSERT", "installation_id", "issuer_epoch", "source_uid", "source_generation", "source_digest", "observed_at", "fresh_until")
	case 1:
		add("goose_db_version", "SELECT")
		add("fleet_initial_activation", "SELECT")
		add("fleet_initial_activation", "UPDATE", "audit_receipt_json")
	case 2:
		add("fleet_current_trust", "SELECT")
		add("fleet_initial_activation", "UPDATE", "activated_at")
		add("fleet_trust", "UPDATE", "suspended", "recovery_blocked", "activated_postmaster_at", "activated_database_oid", "observed_at", "fresh_until", "activated_system_identifier", "activated_timeline")
		add("fleet_observation", "INSERT", "installation_id", "semantic_version", "issuer_epoch", "source_uid", "source_generation", "source_digest", "activated_postmaster_at", "activated_database_oid", "observed_at", "fresh_until")
	}
	return out
}
func (g initialRoleGrant) key() string {
	return g.kind + ":" + g.object + ":" + g.column + ":" + g.privilege
}
func (g initialRoleGrant) sql(verb, role string) string {
	priv := g.privilege
	if g.column != "" {
		priv += "(" + pgx.Identifier{g.column}.Sanitize() + ")"
	}
	object := "TABLE " + pgx.Identifier{"public", g.object}.Sanitize()
	if g.kind == "schema" {
		object = "SCHEMA " + pgx.Identifier{g.object}.Sanitize()
	}
	direction := " TO "
	if verb == "REVOKE" {
		direction = " FROM "
	}
	return verb + " " + priv + " ON " + object + direction + pgx.Identifier{role}.Sanitize()
}

func (s *InitialSQLRoles) transaction(ctx context.Context, p InitialSQLCredentials, fn func(context.Context, pgx.Tx) error) error {
	if s == nil || ctx == nil || !p.valid() || p.InstallationID != s.installation {
		return value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return value.ErrUnavailable
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer done()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, "SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'; SET LOCAL idle_in_transaction_session_timeout='5s'; SET LOCAL synchronous_commit=on; SET LOCAL row_security=off"); err != nil {
		return value.ErrUnavailable
	}
	if err = lockInitialTables(ctx, tx); err != nil {
		return err
	}
	if err = fn(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return value.ErrUnavailable
	}
	return nil
}

func initialRolesCurrent(ctx context.Context, tx pgx.Tx, p InitialSQLCredentials) error {
	_, now, err := initialDatabase(ctx, tx)
	if err != nil || now.Before(p.NotBefore) || !now.Before(p.NotAfter) {
		return value.ErrDenied
	}
	return nil
}

func (s *InitialSQLRoles) Provision(ctx context.Context, p InitialSQLCredentials) error {
	err := s.transaction(ctx, p, func(ctx context.Context, tx pgx.Tx) error {
		if err := initialRolesCurrent(ctx, tx, p); err != nil {
			return err
		}
		names := []string{p.Preparation.Username, p.Audit.Username, p.Activation.Username}
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=ANY($1)", names).Scan(&count); err != nil {
			return value.ErrUnavailable
		}
		if count != 0 && count != 3 {
			return value.ErrConflict
		}
		if count == 0 {
			// Missing credentials/roles after any operational use are recovery,
			// never permission to rebootstrap or silently recreate authority.
			for _, name := range initialInstallationTables {
				if name == "goose_db_version" {
					continue
				}
				var exists bool
				query := "SELECT EXISTS(SELECT 1 FROM " + pgx.Identifier{"public", name}.Sanitize() + ")"
				args := []any{}
				if name == "fleet_trust" {
					query = "SELECT EXISTS(SELECT 1 FROM public.fleet_trust WHERE installation_id<>$1 OR NOT suspended OR NOT recovery_blocked OR activated_postmaster_at IS NOT NULL OR activated_database_oid IS NOT NULL)"
					args = append(args, p.InstallationID)
				}
				if err := tx.QueryRow(ctx, query, args...).Scan(&exists); err != nil || exists {
					return value.ErrDenied
				}
			}
			for i, l := range p.logins() {
				verifier, err := initialPasswordVerifier(l)
				if err != nil {
					return err
				}
				// Verifier alphabet and formatted timestamp contain no SQL quotes.
				statement := "CREATE ROLE " + pgx.Identifier{l.Username}.Sanitize() + " LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4 PASSWORD '" + verifier + "' VALID UNTIL '" + p.NotAfter.UTC().Format(time.RFC3339) + "'"
				if _, err = tx.Exec(ctx, statement); err != nil {
					return value.ErrUnavailable
				}
				for _, g := range initialRoleGrants(i) {
					if _, err = tx.Exec(ctx, g.sql("GRANT", l.Username)); err != nil {
						return value.ErrUnavailable
					}
				}
			}
		}
		if err := s.verify(ctx, tx, p, false); err != nil {
			return err
		}
		return initialRolesCurrent(ctx, tx, p)
	})
	if err != nil {
		return err
	}
	// Authenticate each supplied secret through a fresh TLS/SCRAM connection.
	// Matching role names/ACLs alone must never adopt an unrelated credential.
	for _, l := range p.logins() {
		check, end := context.WithDeadline(ctx, p.NotAfter)
		check, short := context.WithTimeout(check, 5*time.Second)
		c := s.pool.Config().ConnConfig.Copy()
		c.User, c.Password, c.RequireAuth = l.Username, l.Password, "scram-sha-256"
		c.ValidateConnect, c.AfterConnect = nil, nil
		conn, e := pgx.ConnectConfig(check, c)
		if e == nil {
			e = conn.Ping(check)
			_ = conn.Close(check)
		}
		short()
		end()
		if e != nil {
			return value.ErrDenied
		}
	}
	return nil
}

func (s *InitialSQLRoles) verify(ctx context.Context, tx pgx.Tx, p InitialSQLCredentials, retired bool) error {
	// Direct grants alone do not describe effective permissions: PUBLIC access
	// and callable SECURITY DEFINER functions can bypass all purpose boundaries.
	// The dedicated installation database permits ordinary system catalog and
	// database CONNECT/TEMP access, but never ambient application/DDL authority.
	var ambient bool
	err := tx.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee=0 AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')
 OR EXISTS(SELECT 1 FROM pg_attribute x JOIN pg_class c ON c.oid=x.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(x.attacl) a WHERE a.grantee=0 AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')
 OR EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE a.grantee=0 AND a.privilege_type='CREATE')
 OR EXISTS(SELECT 1 FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a WHERE a.grantee=0 AND a.privilege_type='CREATE')`).Scan(&ambient)
	if err != nil || ambient {
		return value.ErrConflict
	}
	for i, l := range p.logins() {
		var flags bool
		var expiry pgtype.Timestamptz
		var oid uint32
		err := tx.QueryRow(ctx, `SELECT oid,NOT rolsuper AND NOT rolinherit AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolconnlimit=4 AND rolcanlogin=$2,rolvaliduntil FROM pg_roles WHERE rolname=$1`, l.Username, !retired).Scan(&oid, &flags, &expiry)
		if err != nil || !flags || !expiry.Valid || !expiry.Time.Equal(p.NotAfter) {
			return value.ErrConflict
		}
		var unsafe bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=$1 OR (roleid=$1 AND member<>(SELECT oid FROM pg_roles WHERE rolname=current_user)))
 OR EXISTS(SELECT 1 FROM pg_class WHERE relowner=$1) OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspowner=$1)
 OR EXISTS(SELECT 1 FROM pg_database WHERE datdba=$1) OR EXISTS(SELECT 1 FROM pg_proc WHERE proowner=$1)
 OR EXISTS(SELECT 1 FROM pg_db_role_setting WHERE setrole=$1)
 OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema') AND has_function_privilege($1::oid,p.oid,'EXECUTE'))`, oid).Scan(&unsafe)
		if err != nil || unsafe {
			return value.ErrConflict
		}
		rows, err := tx.Query(ctx, `SELECT 'table',n.nspname||'.'||c.relname,'',a.privilege_type,a.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'table',n.nspname||'.'||c.relname,x.attname,a.privilege_type,a.is_grantable FROM pg_attribute x JOIN pg_class c ON c.oid=x.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(x.attacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'schema',nspname,'',a.privilege_type,a.is_grantable FROM pg_namespace CROSS JOIN LATERAL aclexplode(nspacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'database',datname,'',a.privilege_type,a.is_grantable FROM pg_database CROSS JOIN LATERAL aclexplode(datacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'function',proname,'',a.privilege_type,a.is_grantable FROM pg_proc CROSS JOIN LATERAL aclexplode(proacl) a WHERE a.grantee=$1`, oid)
		if err != nil {
			return value.ErrUnavailable
		}
		actual := []string{}
		for rows.Next() {
			var g initialRoleGrant
			var grantable bool
			if err = rows.Scan(&g.kind, &g.object, &g.column, &g.privilege, &grantable); err != nil || grantable {
				rows.Close()
				return value.ErrConflict
			}
			if g.kind == "table" {
				if !strings.HasPrefix(g.object, "public.") {
					rows.Close()
					return value.ErrConflict
				}
				g.object = strings.TrimPrefix(g.object, "public.")
			}
			actual = append(actual, g.key())
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return value.ErrUnavailable
		}
		want := []string{}
		if !retired {
			for _, g := range initialRoleGrants(i) {
				want = append(want, g.key())
			}
		}
		slices.Sort(actual)
		slices.Sort(want)
		if !slices.Equal(actual, want) {
			return value.ErrConflict
		}
	}
	return nil
}

// Retire never drops/recreates names or enables a login. It excludes in-flight
// application transactions with the same table locks, revokes column as well as
// table/schema grants and disables password and new-login authentication.
// Provider/Kubernetes cleanup and confirmation of process termination remain
// the installation supervisor's responsibility.
func (s *InitialSQLRoles) Retire(ctx context.Context, p InitialSQLCredentials) error {
	return s.transaction(ctx, p, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.verify(ctx, tx, p, true); err == nil {
			return nil
		}
		if err := s.verify(ctx, tx, p, false); err != nil {
			return err
		}
		for i, l := range p.logins() {
			if _, err := tx.Exec(ctx, "ALTER ROLE "+pgx.Identifier{l.Username}.Sanitize()+" NOLOGIN PASSWORD NULL"); err != nil {
				return value.ErrUnavailable
			}
			for _, g := range initialRoleGrants(i) {
				if _, err := tx.Exec(ctx, g.sql("REVOKE", l.Username)); err != nil {
					return value.ErrUnavailable
				}
			}
		}
		return s.verify(ctx, tx, p, true)
	})
}

// Keep accidental formatting of a secret plan opaque in errors and logs.
func (InitialSQLCredentials) String() string   { return "protected initial SQL credentials" }
func (InitialSQLCredentials) GoString() string { return "protected initial SQL credentials" }
func (InitialSQLLogin) String() string         { return "protected initial SQL login" }
func (InitialSQLLogin) GoString() string       { return "protected initial SQL login" }

var _ fmt.Stringer = InitialSQLCredentials{}
