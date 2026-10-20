package integration

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"github.com/jackc/pgx/v5"
)

const activityInstallation = "10000000-0000-4000-8000-000000000001"

type activityRows struct {
	pgx.Rows
	left, next, scans int
	closed            bool
	role, event       string
	scanErr, readErr  error
	beforeNext        func()
}

func (r *activityRows) Close()     { r.closed = true }
func (r *activityRows) Err() error { return r.readErr }
func (r *activityRows) Next() bool {
	r.next++
	if r.beforeNext != nil {
		r.beforeNext()
	}
	if r.left == 0 {
		return false
	}
	r.left--
	return true
}
func (r *activityRows) Scan(out ...any) error {
	r.scans++
	if r.scanErr != nil {
		return r.scanErr
	}
	*out[0].(*string) = r.role
	*out[1].(*string) = "idle in transaction"
	*out[2].(*string) = "Client"
	*out[3].(*string) = r.event
	*out[4].(*int64) = 3100
	*out[5].(*int64) = 3000
	return nil
}

func TestInstalledSQLActivityUsesOnlyBoundedReadProjection(t *testing.T) {
	registry, _ := postgres.OwnerIdentityRoleName(activityInstallation, "registry")
	rows := &activityRows{left: 1000, role: registry, event: "ClientRead"}
	var output strings.Builder
	queries := 0
	started := time.Now()
	installedSQLActivityDiagnostics(t.Context(), func(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
		queries++
		until, ok := ctx.Deadline()
		if !ok || until.After(started.Add(2100*time.Millisecond)) {
			t.Fatal("unbounded diagnostic call")
		}
		lower := strings.ToLower(query)
		if !strings.HasPrefix(lower, "select ") || !strings.Contains(lower, "from pg_catalog.pg_stat_activity") ||
			!strings.Contains(lower, "datname = current_database()") || !strings.Contains(lower, "usename = any($1::text[])") ||
			!strings.Contains(lower, "limit 65") || len(args) != 1 {
			t.Fatal("query lost fixed read-only scope or bound")
		}
		if regexp.MustCompile(`\b(query|application_name|client_addr|client_hostname|client_port|password|set|insert|update|delete)\b`).MatchString(lower) {
			t.Fatal("sensitive field or mutation in diagnostic query")
		}
		roles := args[0].([]string)
		source, _ := postgres.ConfigurationRuntimeRoleName(activityInstallation, "configuration-source")
		capture, _ := postgres.PublicRuntimeRoleName(activityInstallation, "capture-journal")
		foreign, _ := postgres.OwnerIdentityRoleName("20000000-0000-4000-8000-000000000002", "registry")
		if !slices.Contains(roles, registry) || !slices.Contains(roles, source) || !slices.Contains(roles, capture) ||
			slices.Contains(roles, foreign) || slices.Contains(roles, "postgres") {
			t.Fatal("diagnostic roles are not the installation's runtime roles")
		}
		return rows, nil
	}, activityInstallation, func(format string, args ...any) { fmt.Fprintf(&output, format+"\n", args...) })
	text := output.String()
	if queries != 1 || !rows.closed || rows.next != 65 || rows.scans != 64 ||
		strings.Count(text, "SQL activity role=") != 64 || !strings.Contains(text, "truncated at 64 rows") ||
		!strings.Contains(text, `state="idle in transaction" wait_type="Client" event="ClientRead" transaction_ms=3100 query_ms=3000`) ||
		len(text) > 64*256+80 {
		t.Fatal("diagnostic output or resource lifetime is not bounded", queries, rows.closed, rows.next, rows.scans, len(text))
	}
}

func TestInstalledSQLActivityRedactsFailuresAndRejectsUnexpectedRows(t *testing.T) {
	role, _ := postgres.OwnerIdentityRoleName(activityInstallation, "registry")
	const sensitive = "provider password=secret SELECT user_data"
	for _, tc := range []struct {
		name, role, event, want    string
		queryErr, scanErr, readErr error
		left                       int
	}{
		{name: "query", queryErr: errors.New(sensitive), want: "(query)"},
		{name: "scan", role: role, left: 1, scanErr: errors.New(sensitive), want: "(row)"},
		{name: "read", readErr: errors.New(sensitive), want: "(read)"},
		{name: "foreign-role", role: sensitive, left: 1, want: "(row)"},
		{name: "oversized-event", role: role, event: strings.Repeat(sensitive, 10), left: 1, want: "(row)"},
		{name: "empty", want: "rows=0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := &activityRows{left: tc.left, role: tc.role, event: tc.event, scanErr: tc.scanErr, readErr: tc.readErr}
			var output strings.Builder
			installedSQLActivityDiagnostics(t.Context(), func(context.Context, string, ...any) (pgx.Rows, error) {
				if tc.queryErr != nil {
					return nil, tc.queryErr
				}
				return rows, nil
			}, activityInstallation, func(format string, args ...any) { fmt.Fprintf(&output, format+"\n", args...) })
			text := output.String()
			if strings.Contains(text, sensitive) || !strings.Contains(text, tc.want) || len(text) > 100 ||
				(tc.queryErr == nil && !rows.closed) {
				t.Fatal("diagnostic leaked provider detail or did not close rows", text, rows.closed)
			}
		})
	}
}

func TestInstalledSQLActivityKeepsOriginalCancellationAndDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	until, _ := ctx.Deadline()
	role, _ := postgres.OwnerIdentityRoleName(activityInstallation, "registry")
	rows := &activityRows{left: 1, role: role, beforeNext: cancel}
	calls := 0
	var stages []string
	read := func(call context.Context, _ string, _ ...any) (pgx.Rows, error) {
		calls++
		got, ok := call.Deadline()
		if !ok || !got.Equal(until) {
			t.Fatal("diagnostic extended original deadline")
		}
		return rows, nil
	}
	logf := func(format string, args ...any) { stages = append(stages, fmt.Sprintf(format, args...)) }
	installedSQLActivityDiagnostics(ctx, read, activityInstallation, logf)
	installedSQLActivityDiagnostics(ctx, read, activityInstallation, logf)
	if calls != 1 || rows.scans != 0 || !rows.closed || len(stages) != 2 {
		t.Fatal("cancellation allowed another read or failed to close rows", calls, rows.scans, rows.closed, stages)
	}
	for _, stage := range stages {
		if !strings.HasSuffix(stage, "(caller)") {
			t.Fatal("cancellation was not propagated", stage)
		}
	}
}
