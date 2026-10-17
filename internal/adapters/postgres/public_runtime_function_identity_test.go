package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
)

// This catalog double models PostgreSQL 18's two distinct facts: the compiled
// timestamptz spelling resolves to an exact overload, while oidvectortypes
// renders timestamp with time zone. Actual provider shape is separately asserted
// by the SQL54 native fixture; this test exercises the complete verifier.
type functionIdentityCatalog struct {
	resolved                  string
	actual                    string
	foreign, grantable, extra bool
	provenance                []byte
}

func (c functionIdentityCatalog) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	return functionIdentityRow(func(dst ...any) error {
		switch {
		case strings.Contains(query, "rolcanlogin"):
			*dst[0].(*uint32), *dst[1].(*bool), *dst[2].(*string) = 1234, true, string(c.provenance)
		case strings.Contains(query, "pg_auth_members"):
			*dst[0].(*bool) = false
		case strings.Contains(query, "p.prosecdef"):
			*dst[0].(*bool) = false
			if len(dst) == 2 {
				*dst[1].(*[]string) = []string{c.resolved}
			}
		default:
			return errors.New("unexpected catalog query")
		}
		return nil
	})
}
func (c functionIdentityCatalog) Query(_ context.Context, query string, _ ...any) (pgx.Rows, error) {
	object := "public.capacity_managed_admission_until(uuid,uuid,text,timestampwithtimezone)"
	if strings.Contains(query, "n.nspname||'.'||p.oid::text") {
		object = "public." + c.actual
	}
	if c.foreign {
		object = strings.Replace(object, "public.", "foreign.", 1)
	}
	rows := &functionIdentityRows{at: -1, values: [][]any{
		{"schema", "public", "", "USAGE", false},
		{"table", "public.goose_db_version", "", "SELECT", false},
		{"function", object, "", "EXECUTE", c.grantable},
	}}
	if c.extra {
		rows.values = append(rows.values, []any{"function", "public.6001", "", "EXECUTE", false})
	}
	return rows, nil
}

type functionIdentityRow func(...any) error

func (r functionIdentityRow) Scan(dst ...any) error { return r(dst...) }

type functionIdentityRows struct {
	pgx.Rows
	at     int
	values [][]any
}

func (r *functionIdentityRows) Close()     {}
func (r *functionIdentityRows) Err() error { return nil }
func (r *functionIdentityRows) Next() bool { r.at++; return r.at < len(r.values) }
func (r *functionIdentityRows) Scan(dst ...any) error {
	for i, value := range r.values[r.at] {
		switch v := value.(type) {
		case string:
			*dst[i].(*string) = v
		case bool:
			*dst[i].(*bool) = v
		default:
			return errors.New("unexpected catalog value")
		}
	}
	return nil
}

func TestFixedRuntimeRoleFunctionAliasUsesExactOverload(t *testing.T) {
	grants := []publicRuntimeGrant{
		{"schema", "public", "", "USAGE"},
		{"table", "goose_db_version", "", "SELECT"},
		{"function", "capacity_managed_admission_until(uuid,uuid,text,timestamptz)", "", "EXECUTE"},
	}
	for _, tc := range []struct {
		name   string
		change func(*functionIdentityCatalog)
		valid  bool
	}{
		{"same-overload-despite-type-display-alias", func(*functionIdentityCatalog) {}, true},
		{"different-overload", func(c *functionIdentityCatalog) { c.actual = "4568" }, false},
		{"unresolved-compiled-overload", func(c *functionIdentityCatalog) { c.resolved = "" }, false},
		{"zero-oid", func(c *functionIdentityCatalog) { c.resolved = "0" }, false},
		{"foreign-schema", func(c *functionIdentityCatalog) { c.foreign = true }, false},
		{"extra-function", func(c *functionIdentityCatalog) { c.extra = true }, false},
		{"grant-option", func(c *functionIdentityCatalog) { c.grantable = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := functionIdentityCatalog{resolved: "4567", actual: "4567", provenance: []byte("synthetic-original-public-provenance")}
			tc.change(&c)
			receipt, err := verifyFixedRuntimeRole(context.Background(), c, "synthetic-role", 3, "synthetic-layout", nil, c.provenance, grants)
			if tc.valid {
				if err != nil || receipt.RoleOID != 1234 || receipt.LayoutDigest != "synthetic-layout" {
					t.Fatalf("exact function overload rejected due to alias display: %v", err)
				}
			} else if !errors.Is(err, cfg.ErrChanged) {
				t.Fatalf("non-exact catalog accepted: %v", err)
			}
		})
	}
}
