package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// fixtureGrantsSQL lists every explicit table, sequence, column and function
// grant in the public schema as an idempotent GRANT statement. The owner's
// implicit rights and PUBLIC grants are left out.
const fixtureGrantsSQL = `
SELECT format('GRANT %s ON %s %I.%I TO %I', x.privilege_type, CASE WHEN c.relkind='S' THEN 'SEQUENCE' ELSE 'TABLE' END, n.nspname, c.relname, r.rolname)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) x JOIN pg_roles r ON r.oid=x.grantee
WHERE n.nspname='public' AND c.relacl IS NOT NULL AND x.grantee<>c.relowner
UNION ALL
SELECT format('GRANT %s(%I) ON TABLE %I.%I TO %I', x.privilege_type, a.attname, n.nspname, c.relname, r.rolname)
FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(a.attacl) x JOIN pg_roles r ON r.oid=x.grantee
WHERE n.nspname='public' AND a.attacl IS NOT NULL AND NOT a.attisdropped AND x.grantee<>c.relowner
UNION ALL
SELECT format('GRANT EXECUTE ON FUNCTION %s TO %I', p.oid::regprocedure, r.rolname)
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(p.proacl) x JOIN pg_roles r ON r.oid=x.grantee
WHERE n.nspname='public' AND p.proacl IS NOT NULL AND x.grantee<>p.proowner AND x.privilege_type='EXECUTE'`

// preserveFixtureGrants snapshots the explicit grants before a downgrade
// probe. A migration Down that drops a column, table or function also drops
// the fixture role grants test/fixtures/sql/runtime-roles.sql made on it, and
// re-running its Up does not restore them, so every later case sharing the
// owned database would fail with permission denied. The returned restore runs
// after the schema is back at its original head and re-grants exactly the
// snapshot (GRANT is idempotent; nothing is revoked or widened).
func preserveFixtureGrants(t *testing.T, ctx context.Context, admin *pgxpool.Pool) func(context.Context) {
	t.Helper()
	grants, err := listFixtureGrants(ctx, admin)
	if err != nil || len(grants) == 0 {
		t.Fatal("snapshot fixture grants", len(grants), err)
	}
	return func(ctx context.Context) {
		for _, g := range grants {
			if _, err := admin.Exec(ctx, g); err != nil {
				t.Error("restore fixture grant", g, err)
				return
			}
		}
		after, err := listFixtureGrants(ctx, admin)
		if err != nil {
			t.Error("verify restored fixture grants", err)
			return
		}
		have := map[string]bool{}
		for _, g := range after {
			have[g] = true
		}
		for _, g := range grants {
			if !have[g] {
				t.Error("fixture grant not restored", g)
			}
		}
	}
}

func listFixtureGrants(ctx context.Context, admin *pgxpool.Pool) ([]string, error) {
	rows, err := admin.Query(ctx, fixtureGrantsSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var grants []string
	for rows.Next() {
		var g string
		if err = rows.Scan(&g); err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}
