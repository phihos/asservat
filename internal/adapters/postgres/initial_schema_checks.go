package postgres

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
)

type initialSchemaQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func initialSchemaHistory(ctx context.Context, q initialSchemaQuery, maximum int64, owner uint32) (int64, bool, error) {
	var exists bool
	if e := q.QueryRowContext(ctx, "SELECT to_regclass('public.goose_db_version') IS NOT NULL").Scan(&exists); e != nil {
		return 0, false, cfg.ErrUnavailable
	}
	if !exists {
		return 0, false, nil
	}
	var safe bool
	if e := q.QueryRowContext(ctx, `SELECT c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
 AND c.relowner=$1
 AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=c.oid AND NOT tgisinternal)
 AND (SELECT count(*) FROM pg_constraint WHERE conrelid=c.oid)=5
 AND (SELECT count(*) FROM pg_constraint WHERE conrelid=c.oid AND contype='p' AND conkey=ARRAY[1]::smallint[])=1
 AND (SELECT array_agg(conkey[1] ORDER BY conkey[1]) FROM pg_constraint WHERE conrelid=c.oid AND contype='n' AND cardinality(conkey)=1)=ARRAY[1,2,3,4]::smallint[]
 AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=c.oid AND (contype NOT IN ('p','n') OR condeferrable OR condeferred OR NOT conenforced OR NOT convalidated OR NOT conislocal OR coninhcount<>0 OR conparentid<>0))
 FROM pg_class c WHERE c.oid='public.goose_db_version'::regclass`, owner).Scan(&safe); e != nil || !safe {
		return 0, false, cfg.ErrChanged
	}
	rows, e := q.QueryContext(ctx, `SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,COALESCE(pg_get_expr(d.adbin,d.adrelid),'') FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.goose_db_version'::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`)
	if e != nil {
		return 0, false, cfg.ErrUnavailable
	}
	type column struct {
		name, kind             string
		required               bool
		identity, defaultValue string
	}
	expected := []column{{"id", "integer", true, "d", ""}, {"version_id", "bigint", true, "", ""}, {"is_applied", "boolean", true, "", ""}, {"tstamp", "timestamp without time zone", true, "", "now()"}}
	i := 0
	for rows.Next() {
		var actual column
		if e = rows.Scan(&actual.name, &actual.kind, &actual.required, &actual.identity, &actual.defaultValue); e != nil || i >= len(expected) || actual != expected[i] {
			rows.Close()
			return 0, false, cfg.ErrChanged
		}
		i++
	}
	e = rows.Err()
	rows.Close()
	if e != nil || i != len(expected) {
		return 0, false, cfg.ErrChanged
	}
	rows, e = q.QueryContext(ctx, "SELECT id,version_id,is_applied,tstamp FROM public.goose_db_version ORDER BY id LIMIT 130")
	if e != nil {
		return 0, false, cfg.ErrUnavailable
	}
	defer rows.Close()
	entries := []initialSchemaVersion{}
	for rows.Next() {
		var v initialSchemaVersion
		if e = rows.Scan(&v.ID, &v.Version, &v.Applied, &v.At); e != nil {
			return 0, false, cfg.ErrUnavailable
		}
		entries = append(entries, v)
	}
	if rows.Err() != nil {
		return 0, false, cfg.ErrUnavailable
	}
	head, e := initialSchemaPrefix(entries, maximum)
	return head, true, e
}

type initialSchemaVersion struct {
	ID, Version int64
	Applied     bool
	At          time.Time
}

func initialSchemaPrefix(entries []initialSchemaVersion, maximum int64) (int64, error) {
	if len(entries) == 0 || len(entries) > int(maximum+1) || maximum < 1 || maximum > 128 {
		return 0, cfg.ErrChanged
	}
	var lastID int64
	var lastTime time.Time
	for i, v := range entries {
		if v.ID <= lastID || v.Version != int64(i) || !v.Applied || v.At.Year() < 2020 || v.At.Year() > 9998 || (!lastTime.IsZero() && v.At.Before(lastTime)) {
			return 0, cfg.ErrChanged
		}
		lastID, lastTime = v.ID, v.At
	}
	return int64(len(entries) - 1), nil
}

func initialSchemaInventory(ctx context.Context, q initialSchemaQuery, complete, empty bool, owner uint32) error {
	var extra bool
	if e := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT IN ('public','pg_catalog','information_schema') AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp_%')`).Scan(&extra); e != nil || extra {
		return cfg.ErrChanged
	}
	rows, e := q.QueryContext(ctx, `SELECT c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,c.relowner=$1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','f','m') ORDER BY c.relname LIMIT 129`, owner)
	if e != nil {
		return cfg.ErrUnavailable
	}
	names := []string{}
	for rows.Next() {
		var name, kind, persistence string
		var rls, force, owner bool
		if e = rows.Scan(&name, &kind, &persistence, &rls, &force, &owner); e != nil || kind != "r" || persistence != "p" || rls || force || !owner || !slices.Contains(initialInstallationTables, name) {
			rows.Close()
			return cfg.ErrChanged
		}
		names = append(names, name)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(names) > 128 {
		return cfg.ErrChanged
	}
	if complete && !slices.Equal(names, initialInstallationTables) {
		return cfg.ErrChanged
	}
	if !complete && len(names) == 0 {
		// The first claim additionally rejects preexisting user functions/views and
		// sequences: absence of ordinary table rows alone is not a fresh schema.
		if e = q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')`).Scan(&extra); e != nil || extra {
			return cfg.ErrChanged
		}
	}
	if empty {
		for _, name := range names {
			if name == "goose_db_version" {
				continue
			}
			var present bool
			if e = q.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+pgx.Identifier{"public", name}.Sanitize()+")").Scan(&present); e != nil || present {
				return cfg.ErrChanged
			}
		}
	}
	if ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

func initialSchemaManager(ctx context.Context, q initialSchemaQuery, pin contracts.InitialSQLHistoryManager, requireGrants bool) error {
	if !validInitialHistoryManager(pin) {
		return cfg.ErrInvalid
	}
	var safe bool
	if e := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE oid=$1 AND rolname=$2 AND rolcanlogin AND NOT rolsuper AND rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND (rolvaliduntil IS NULL OR rolvaliduntil>clock_timestamp()))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=$1)
 AND NOT EXISTS(SELECT 1 FROM pg_class WHERE relowner=$1)
 AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspowner=$1)
 AND NOT EXISTS(SELECT 1 FROM pg_database WHERE datdba=$1)
 AND NOT EXISTS(SELECT 1 FROM pg_proc WHERE proowner=$1)
 AND NOT EXISTS(SELECT 1 FROM pg_db_role_setting WHERE setrole=$1)`, pin.OID, pin.Name).Scan(&safe); e != nil || !safe {
		return cfg.ErrChanged
	}
	rows, e := q.QueryContext(ctx, `SELECT 'table',n.nspname||'.'||c.relname,'',a.privilege_type,a.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'table',n.nspname||'.'||c.relname,x.attname,a.privilege_type,a.is_grantable FROM pg_attribute x JOIN pg_class c ON c.oid=x.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(x.attacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'schema',nspname,'',a.privilege_type,a.is_grantable FROM pg_namespace CROSS JOIN LATERAL aclexplode(nspacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'database',datname,'',a.privilege_type,a.is_grantable FROM pg_database CROSS JOIN LATERAL aclexplode(datacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'function',proname,'',a.privilege_type,a.is_grantable FROM pg_proc CROSS JOIN LATERAL aclexplode(proacl) a WHERE a.grantee=$1`, pin.OID)
	if e != nil {
		return cfg.ErrUnavailable
	}
	defer rows.Close()
	actual := []string{}
	for rows.Next() {
		var g initialRoleGrant
		var grantable bool
		if e = rows.Scan(&g.kind, &g.object, &g.column, &g.privilege, &grantable); e != nil || !grantable {
			return cfg.ErrChanged
		}
		if g.kind == "table" {
			if !strings.HasPrefix(g.object, "public.") {
				return cfg.ErrChanged
			}
			g.object = strings.TrimPrefix(g.object, "public.")
		}
		actual = append(actual, g.key())
		if len(actual) > 512 {
			return cfg.ErrChanged
		}
	}
	if rows.Err() != nil {
		return cfg.ErrUnavailable
	}
	want := []string{}
	for _, g := range initialSchemaManagerGrants() {
		want = append(want, g.key())
	}
	slices.Sort(actual)
	slices.Sort(want)
	if (requireGrants || len(actual) != 0) && !slices.Equal(actual, want) {
		return cfg.ErrChanged
	}
	if ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	return nil
}
func initialSchemaManagerGrants() []initialRoleGrant {
	result := []initialRoleGrant{}
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		for _, g := range initialRoleGrants(i) {
			if !seen[g.key()] {
				seen[g.key()] = true
				result = append(result, g)
			}
		}
	}
	return result
}
func grantInitialSchemaManager(ctx context.Context, conn *sql.Conn, pin contracts.InitialSQLHistoryManager) error {
	// Exact completed grants are replay, never a reason to issue them again.
	if e := initialSchemaManager(ctx, conn, pin, true); e == nil {
		return nil
	}
	if e := initialSchemaManager(ctx, conn, pin, false); e != nil {
		return e
	}
	tx, e := conn.BeginTx(ctx, nil)
	if e != nil {
		return cfg.ErrUnavailable
	}
	defer tx.Rollback()
	for _, g := range initialSchemaManagerGrants() {
		if _, e = tx.ExecContext(ctx, g.sql("GRANT", pin.Name)+" WITH GRANT OPTION"); e != nil {
			return cfg.ErrUnavailable
		}
	}
	if e = initialSchemaManager(ctx, tx, pin, true); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	if e = tx.Commit(); e != nil {
		return cfg.ErrUnavailable
	}
	return initialSchemaManager(ctx, conn, pin, true)
}

// CheckManager observes the independently pinned trusted manager without
// granting, creating or resetting it. Before schema installation it accepts no
// application grants; after installation it also accepts the exact grant union.
func (s *InitialSchema) CheckManager(ctx context.Context) error {
	if s == nil || ctx == nil {
		return cfg.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	return initialSchemaManager(ctx, s.db, s.manager, false)
}

func initialSchemaEmpty(ctx context.Context, q initialSchemaQuery, owner uint32) error {
	if e := initialSchemaInventory(ctx, q, false, true, owner); e != nil {
		return e
	}
	var present bool
	if e := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')`).Scan(&present); e != nil || present {
		return cfg.ErrChanged
	}
	return nil
}
