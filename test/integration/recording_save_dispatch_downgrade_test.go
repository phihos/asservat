package integration

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These hooks require genuinely admitted normal-lane request_capture journals.
// They run only when a later owned provider qualifier invokes them; local
// compilation is not downgrade qualification. DDL stays in a rolled-back
// transaction and never changes Goose history, runtime roles or retained rows.
func recordingSaveDispatchDownSQL(t *testing.T) string {
	t.Helper()
	raw, err := fs.ReadFile(migrations.Files(), "00111_recording_save_dispatch_window.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, down, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("missing111Down")
	}
	return down
}
func dispatchGuardDefinition(t *testing.T, ctx context.Context, admin *pgxpool.Pool) string {
	t.Helper()
	var body string
	if err := admin.QueryRow(ctx, "SELECT pg_get_functiondef('public.guard_operation_audit()'::regprocedure)").Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "WHEN NEW.intent->>'Name'='request_capture' THEN interval '15 seconds'") {
		t.Fatal("qualifier requires installed111guard")
	}
	return body
}
func requireDispatchAuditRow(t *testing.T, ctx context.Context, admin *pgxpool.Pool, id string, long bool) {
	t.Helper()
	var actual bool
	err := admin.QueryRow(ctx, `SELECT request_until>(intent->>'CreatedAt')::timestamptz+interval '5 seconds' FROM public.operation_audit WHERE id=$1 AND intent->>'Name'='request_capture'`, id).Scan(&actual)
	if err != nil || actual != long {
		t.Fatal("qualifier requires real matching retained request_capture journal", err, actual, long)
	}
}

// Invoke BEFORE creating the long journal: an existing old-format5s row must
// permit exact prior guard restoration, with evidence20s preserved, then rollback.
func qualifyRecordingSaveDispatchLegacyDowngrade(t *testing.T, ctx context.Context, admin *pgxpool.Pool, shortID string) {
	t.Helper()
	requireDispatchAuditRow(t, ctx, admin, shortID, false)
	before := dispatchGuardDefinition(t, ctx, admin)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, recordingSaveDispatchDownSQL(t)); err != nil {
		t.Fatal("legacy-only111Down", err)
	}
	var restored string
	if err = tx.QueryRow(ctx, "SELECT pg_get_functiondef('public.guard_operation_audit()'::regprocedure)").Scan(&restored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(restored, "WHEN NEW.intent->>'Name'='request_capture' THEN interval '15 seconds'") || !strings.Contains(restored, "THEN interval '20 seconds' ELSE interval '5 seconds'") {
		t.Fatal("legacy downgrade did not restore prior windows")
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if dispatchGuardDefinition(t, ctx, admin) != before {
		t.Fatal("transactional legacy downgrade changed installed guard")
	}
}

// Invoke AFTER genuinely admitting a15s request: even an expired retained
// journal must refuse downgrade before any function changes. The compatible5s
// row remains present and unchanged; no forced deletion masks the refusal.
func qualifyRecordingSaveDispatchPopulatedDowngrade(t *testing.T, ctx context.Context, admin *pgxpool.Pool, longID, shortID string) {
	t.Helper()
	requireDispatchAuditRow(t, ctx, admin, shortID, false)
	requireDispatchAuditRow(t, ctx, admin, longID, true)
	before := dispatchGuardDefinition(t, ctx, admin)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, recordingSaveDispatchDownSQL(t))
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" || pe.Message != "retained long-window capture requests cannot downgrade" {
		t.Fatal("populated111Down did not give exact protocol refusal", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if dispatchGuardDefinition(t, ctx, admin) != before {
		t.Fatal("refused downgrade changed installed guard")
	}
	requireDispatchAuditRow(t, ctx, admin, shortID, false)
	requireDispatchAuditRow(t, ctx, admin, longID, true)
}

// SQL112 hooks exercise actual migration bodies with genuine rows. The first
// runs before any new group and restores the same functions inside rollback;
// the second cannot erase a retained longer-window protocol.
func recordingSaveGroupBoundsSQL(t *testing.T) (string, string) {
	t.Helper()
	raw, err := fs.ReadFile(migrations.Files(), "00112_recording_save_group_request_bounds.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("missing112Down")
	}
	return up, down
}
func groupBoundsDefinition(t *testing.T, ctx context.Context, admin *pgxpool.Pool) string {
	t.Helper()
	var body string
	if err := admin.QueryRow(ctx, "SELECT pg_get_functiondef(to_regprocedure($1::text))", "public.recording_save_group_window_valid(public.context_capture,public.recording_save_group,timestamptz)").Scan(&body); err != nil {
		t.Fatal(err)
	}
	return body
}
func qualifyRecordingSaveGroupBoundsEmptyDownUp(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	before := groupBoundsDefinition(t, ctx, admin)
	up, down := recordingSaveGroupBoundsSQL(t)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, down); err != nil {
		t.Fatal("empty112Down", err)
	}
	var gone bool
	if err = tx.QueryRow(ctx, "SELECT to_regprocedure('public.recording_save_group_window_valid(public.context_capture,public.recording_save_group,timestamptz)') IS NULL").Scan(&gone); err != nil || !gone {
		t.Fatal("112Down did not restore prior protocol", err)
	}
	if _, err = tx.Exec(ctx, up); err != nil {
		t.Fatal("empty112Up", err)
	}
	var restored string
	if err = tx.QueryRow(ctx, "SELECT pg_get_functiondef(to_regprocedure($1::text))", "public.recording_save_group_window_valid(public.context_capture,public.recording_save_group,timestamptz)").Scan(&restored); err != nil || restored != before {
		t.Fatal("112empty restoration changed function", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if groupBoundsDefinition(t, ctx, admin) != before {
		t.Fatal("112empty rollback changed installed function")
	}
}
func qualifyRecordingSaveGroupBoundsPopulatedDowngrade(t *testing.T, ctx context.Context, admin *pgxpool.Pool, parent string) {
	t.Helper()
	var longer int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM context_capture c JOIN operation_audit a ON a.root_id=c.root_id AND a.id=c.intent_operation_id WHERE c.group_id=$1 AND (convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz>c.created_at+interval '5 seconds' AND a.request_until>c.created_at+interval '5 seconds'`, parent).Scan(&longer); err != nil || longer != 16 {
		t.Fatal("qualifier requires all16 genuine retained longer group dates", longer, err)
	}
	before := groupBoundsDefinition(t, ctx, admin)
	_, down := recordingSaveGroupBoundsSQL(t)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, down)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" || pe.Message != "retained long-window manual groups cannot downgrade" {
		t.Fatal("populated112Down did not give exact refusal", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if groupBoundsDefinition(t, ctx, admin) != before {
		t.Fatal("refused112Down changed installed function")
	}
}
