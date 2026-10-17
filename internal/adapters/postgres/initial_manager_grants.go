package postgres

import (
	"context"
	"slices"
	"strings"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// The same compiled three-facet union used by initial-schema. Retirement never
// invents a broad REVOKE ALL/CASCADE or removes child creator ADMIN provenance.
func initialBootstrapManagerGrants() []initialRoleGrant {
	out := []initialRoleGrant{}
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		for _, g := range initialRoleGrants(i) {
			if !seen[g.key()] {
				seen[g.key()] = true
				out = append(out, g)
			}
		}
	}
	return out
}
func checkInitialManagerGrants(ctx context.Context, q initialManagerQuery, oid uint32, empty bool) error {
	rows, e := q.Query(ctx, `SELECT 'table',n.nspname||'.'||c.relname,'',a.privilege_type,a.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'table',n.nspname||'.'||c.relname,x.attname,a.privilege_type,a.is_grantable FROM pg_attribute x JOIN pg_class c ON c.oid=x.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(x.attacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'schema',nspname,'',a.privilege_type,a.is_grantable FROM pg_namespace CROSS JOIN LATERAL aclexplode(nspacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'database',datname,'',a.privilege_type,a.is_grantable FROM pg_database CROSS JOIN LATERAL aclexplode(datacl) a WHERE a.grantee=$1
 UNION ALL SELECT 'function',proname,'',a.privilege_type,a.is_grantable FROM pg_proc CROSS JOIN LATERAL aclexplode(proacl) a WHERE a.grantee=$1`, oid)
	if e != nil {
		return cfg.ErrUnavailable
	}
	defer rows.Close()
	actual := []string{}
	for rows.Next() {
		var g initialRoleGrant
		var grantable bool
		if rows.Scan(&g.kind, &g.object, &g.column, &g.privilege, &grantable) != nil || !grantable {
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
	if rows.Err() != nil || ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	if len(actual) == 0 {
		return nil
	}
	if empty {
		return cfg.ErrChanged
	}
	want := []string{}
	for _, g := range initialBootstrapManagerGrants() {
		want = append(want, g.key())
	}
	slices.Sort(actual)
	slices.Sort(want)
	if !slices.Equal(actual, want) {
		return cfg.ErrChanged
	}
	return nil
}
