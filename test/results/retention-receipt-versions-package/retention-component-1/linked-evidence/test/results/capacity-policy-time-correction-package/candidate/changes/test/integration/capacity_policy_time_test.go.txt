package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type capacityPolicyTimeCase struct{ name, input, canonical string }

func capacityPolicyTimeCases() []capacityPolicyTimeCase {
	return []capacityPolicyTimeCase{
		{"whole-second", "2026-10-13T00:00:00Z", "2026-10-13T00:00:00Z"},
		{"zero-offset", "2026-10-13T00:00:00+00:00", "2026-10-13T00:00:00Z"},
		{"microsecond", "2026-10-13T00:00:00.123456Z", "2026-10-13T00:00:00.123456Z"},
		{"fraction-zeroes", "2026-10-13T00:00:00.123400+00:00", "2026-10-13T00:00:00.1234Z"},
		{"whole-zero-fraction", "2026-10-13T00:00:00.000000Z", "2026-10-13T00:00:00Z"},
		{"one-microsecond", "2026-10-13T00:00:00.000001Z", "2026-10-13T00:00:00.000001Z"},
		{"negative-offset-next-day", "2026-10-13T23:59:59.999999-03:30", "2026-10-14T03:29:59.999999Z"},
		{"positive-offset-previous-year", "2026-01-01T00:30:00+02:00", "2025-12-31T22:30:00Z"},
		{"leap-day", "2024-02-29T23:59:59.100000Z", "2024-02-29T23:59:59.1Z"},
		{"minimum-year", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z"},
		{"maximum-year", "9999-12-31T23:59:59.999999Z", "9999-12-31T23:59:59.999999Z"},
	}
}

// Preflight the exact native vectors with Go's actual timestamp encoder. This
// does not qualify PostgreSQL's helper; the selected real-SQL matrix does that.
func TestCapacityPolicyTimestampVectors(t *testing.T) {
	for _, c := range capacityPolicyTimeCases() {
		t.Run(c.name, func(t *testing.T) {
			v, err := time.Parse(time.RFC3339Nano, c.input)
			if err != nil {
				t.Fatal(err)
			}
			if v.Nanosecond()%1000 != 0 {
				t.Fatal("vector rounds an original instant")
			}
			got, err := json.Marshal(v.UTC())
			want, _ := json.Marshal(c.canonical)
			if err != nil || string(got) != string(want) {
				t.Fatal("canonical vector does not match actual typed encoding", string(got))
			}
		})
	}
}

// The SQL helper only formats an existing original cutoff. These synthetic
// timestamps never enter a root, account, operation or other authority row.
func qualifyCapacityPolicyTimestampSQL(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	for _, zone := range []string{"UTC", "America/St_Johns"} {
		t.Run(zone, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal("timestamp fixture transaction unavailable")
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, `SELECT set_config('TimeZone',$1,true)`, zone); err != nil {
				t.Fatal("timestamp fixture timezone unavailable")
			}
			for _, c := range capacityPolicyTimeCases() {
				t.Run(c.name, func(t *testing.T) {
					v, err := time.Parse(time.RFC3339Nano, c.input)
					if err != nil {
						t.Fatal(err)
					}
					encoded, err := json.Marshal(v.UTC())
					if err != nil {
						t.Fatal(err)
					}
					var actual []byte
					var unchanged bool
					if err = tx.QueryRow(ctx, `SELECT public.capacity_json_timestamp($1::timestamptz), (public.capacity_json_timestamp($1::timestamptz)#>>'{}')::timestamptz=$1::timestamptz`, c.input).Scan(&actual, &unchanged); err != nil {
						t.Fatalf("timestamp helper unavailable sqlstate=%s", capacitySQLState(err))
					}
					if string(actual) != string(encoded) || !unchanged {
						t.Fatal("SQL lifecycle timestamp does not retain exact typed original cutoff")
					}
				})
			}
		})
	}
	for _, c := range []struct {
		name  string
		input any
		state string
	}{
		{"null", nil, "23514"}, {"empty-phase", "", "22007"}, {"malformed", "not-a-date", "22007"},
		{"infinity", "infinity", "23514"}, {"negative-infinity", "-infinity", "23514"},
		{"outside-go-year", "10000-01-01T00:00:00Z", "23514"}, {"bc", "0001-01-01 00:00:00 BC", "23514"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := admin.Exec(ctx, `SELECT public.capacity_json_timestamp($1::timestamptz)`, c.input)
			var driver *pgconn.PgError
			if !errors.As(err, &driver) || driver.Code != c.state {
				t.Fatalf("malformed policy timestamp accepted or wrong failure sqlstate=%s", capacitySQLState(err))
			}
		})
	}
	var public bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='public.capacity_json_timestamp(timestamptz)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE')`).Scan(&public); err != nil || public {
		t.Fatal("policy formatter unexpectedly exposed to runtime roles")
	}
}
