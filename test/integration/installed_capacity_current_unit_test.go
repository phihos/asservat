package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type capacityCurrentRow struct {
	at        time.Time
	checks    []bool
	remaining []pgtype.Int8
	revision  int64
	err       error
}

func (r capacityCurrentRow) Scan(out ...any) error {
	if r.err != nil {
		return r.err
	}
	*out[0].(*time.Time) = r.at
	*out[1].(*[]bool) = r.checks
	*out[2].(*[]pgtype.Int8) = r.remaining
	*out[3].(*int64) = r.revision
	return nil
}

func capacityCurrentGoodRow() capacityCurrentRow {
	return capacityCurrentRow{at: time.Now(), checks: make([]bool, 18), remaining: []pgtype.Int8{{Int64: 1500, Valid: true}, {Int64: -21, Valid: true}, {}, {Int64: 500, Valid: true}, {Int64: 86400000, Valid: true}}, revision: 7}
}

func TestInstalledCapacityCurrentBoundedSanitizedProjection(t *testing.T) {
	var output strings.Builder
	calls := 0
	started := time.Now()
	installedCapacityCurrentDiagnostics(t.Context(), func(ctx context.Context, query string, args ...any) pgx.Row {
		calls++
		until, ok := ctx.Deadline()
		if !ok || until.After(started.Add(2100*time.Millisecond)) {
			t.Fatal("unbounded read")
		}
		if query != installedCapacityCurrentQuery || len(args) != 3 || args[0] != activityInstallation || args[1] != activityInstallation {
			t.Fatal("query lost fixed scope")
		}
		role, _ := postgres.PublicRuntimeRoleName(activityInstallation, "capacity-profile-read")
		if args[2] != role {
			t.Fatal("wrong reader role")
		}
		q := strings.ToLower(query)
		if !strings.Contains(q, "with sampled as materialized (select clock_timestamp() as at)") || !strings.HasSuffix(q, "limit 1") || regexp.MustCompile(`\b(insert|update|delete|password|credential|query_text|expectation_json|scope_json)\b`).MatchString(q) {
			t.Fatal("unsafe diagnostic projection")
		}
		// Raw public configuration may be consulted only inside fixed predicates;
		// the result's four columns are time, booleans, integers and revision.
		if !strings.Contains(q, "select sampled.at, array[") || !strings.Contains(q, "], array[") || !strings.Contains(q, "], coalesce(s.accepted_revision,0)") {
			t.Fatal("diagnostic returns unbounded/source text")
		}
		if strings.Count(q, "case when coalesce(public.capacity_root_configuration_valid(s.root_configuration),false)") != 3 || !strings.Contains(q, "\n then public.connector_digest") {
			t.Fatal("missing/invalid roots reach the strict digest decoder")
		}
		return capacityCurrentGoodRow()
	}, activityInstallation, activityInstallation, func(format string, args ...any) { fmt.Fprintf(&output, format+"\n", args...) })
	text := output.String()
	if calls != 1 || !strings.Contains(text, "(later read, not failed invocation state) accepted_revision=7") || !strings.Contains(text, "permission_remaining_ms=-21") || !strings.Contains(text, "permission_lease_remaining_ms=unknown") || !strings.Contains(text, "root_planned_remaining_ms=86400000") || strings.Count(text, "diagnostics:") != 7 || len(text) > 1800 {
		t.Fatal("unbounded or misleading output", calls, text)
	}
}

func TestInstalledCapacityCurrentRejectsMalformedOrSensitiveFailures(t *testing.T) {
	const sensitive = "provider password=secret SELECT user_data"
	for _, name := range []string{"query", "short-checks", "extra-checks", "short-times", "bad-revision", "zero-time"} {
		t.Run(name, func(t *testing.T) {
			row := capacityCurrentGoodRow()
			switch name {
			case "query":
				row.err = errors.New(sensitive)
			case "short-checks":
				row.checks = row.checks[:17]
			case "extra-checks":
				row.checks = append(row.checks, false)
			case "short-times":
				row.remaining = row.remaining[:4]
			case "bad-revision":
				row.revision = 1 << 60
			case "zero-time":
				row.at = time.Time{}
			}
			var output strings.Builder
			installedCapacityCurrentDiagnostics(t.Context(), func(context.Context, string, ...any) pgx.Row { return row }, activityInstallation, activityInstallation, func(f string, a ...any) { fmt.Fprintf(&output, f, a...) })
			if output.String() != "diagnostics: capacity current unavailable (read)" {
				t.Fatal("leaked error or malformed row", output.String())
			}
		})
	}
}

func TestInstalledCapacityCurrentOriginalDeadlineAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	until, _ := ctx.Deadline()
	calls := 0
	read := func(call context.Context, _ string, _ ...any) pgx.Row {
		calls++
		got, ok := call.Deadline()
		if !ok || !got.Equal(until) {
			t.Fatal("extended original deadline")
		}
		cancel()
		return capacityCurrentGoodRow()
	}
	var output strings.Builder
	logf := func(f string, a ...any) { fmt.Fprintf(&output, f+"\n", a...) }
	installedCapacityCurrentDiagnostics(ctx, read, activityInstallation, activityInstallation, logf)
	installedCapacityCurrentDiagnostics(ctx, read, activityInstallation, activityInstallation, logf)
	installedCapacityCurrentDiagnostics(t.Context(), read, "invalid", activityInstallation, logf)
	if calls != 1 || output.String() != "diagnostics: capacity current unavailable (read)\ndiagnostics: capacity current unavailable (caller)\ndiagnostics: capacity current unavailable (scope)\n" {
		t.Fatal("canceled diagnostic continued or disclosed data", calls, output.String())
	}
}

// Compile and decode the actual fixed projection against the existing migrated
// PostgreSQL fixture, without fabricating an installation or mutating state.
// This covers missing-row/NULL decoding, not installed current-state proof.
func TestInstalledCapacityCurrentProjectionWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("owned custody PostgreSQL fixture required")
	}
	raw, err := os.ReadFile(path)
	var f fixture
	if err != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal("SQL fixture unavailable")
	}
	defer admin.Close()
	var output strings.Builder
	installedCapacityCurrentDiagnostics(ctx, admin.QueryRow, custodyID(), custodyID(), func(format string, args ...any) { fmt.Fprintf(&output, format+"\n", args...) })
	text := output.String()
	if strings.Contains(text, "unavailable") || !strings.Contains(text, "trust_present=false permission_present=false source_present=false") || !strings.Contains(text, "accepted_revision=0") || strings.Count(text, "remaining_ms=unknown") != 5 {
		t.Fatal("actual SQL missing-row projection failed", text)
	}
	// Exercise the same SQL expressions against an explicitly synthetic typed
	// source record. This adds no table row and tests all strict root decoders.
	root, installation := custodyID(), custodyID()
	malformed, _ := json.Marshal(map[string]any{"root_id": root, "installation_id": installation, "root_configuration": map[string]any{"ReadyAt": "private-fixture-invalid-time", "PlannedUntil": "private-fixture-invalid-time", "PlanDigest": "private-fixture-invalid-digest"}})
	output.Reset()
	installedCapacityCurrentDiagnostics(ctx, func(call context.Context, query string, args ...any) pgx.Row {
		query = strings.Replace(query, "LEFT JOIN public.capacity_source s ON", "LEFT JOIN jsonb_populate_record(NULL::public.capacity_source,$4::jsonb) s ON", 1)
		return admin.QueryRow(call, query, append(args, malformed)...)
	}, root, installation, func(format string, args ...any) { fmt.Fprintf(&output, format+"\n", args...) })
	text = output.String()
	if strings.Contains(text, "unavailable") || strings.Contains(text, "private-fixture") || !strings.Contains(text, "source_present=true") || !strings.Contains(text, "root_configuration_valid=false root_ready=false") || !strings.Contains(text, "root_digest_matches=false") || !strings.Contains(text, "root_planned_remaining_ms=unknown") {
		t.Fatal("actual SQL malformed-root projection failed", text)
	}
}
