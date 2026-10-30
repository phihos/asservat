package postgres

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"io/fs"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/migrations"
)

// Preserve every existing guard predicate; only one operation's prospective
// request budget changes. No authority/child deadline or write window changes.
func TestRecordingSaveDispatchWindowPreservesAuditGuard(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		b, e := fs.ReadFile(migrations.Files(), name)
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	function := func(s string) string {
		t.Helper()
		_, s, ok := strings.Cut(s, "-- +goose StatementBegin\n")
		if !ok {
			t.Fatal("missing function")
		}
		s, _, ok = strings.Cut(s, "-- +goose StatementEnd")
		if !ok {
			t.Fatal("unterminated function")
		}
		return s
	}
	previous := function(read("00077_evidence_read_request_window.sql"))
	current := read("00111_recording_save_dispatch_window.sql")
	old := "THEN interval '20 seconds' ELSE interval '5 seconds' END)"
	new := "THEN interval '20 seconds' WHEN NEW.intent->>'Name'='request_capture' THEN interval '15 seconds' ELSE interval '5 seconds' END)"
	if strings.Count(previous, old) != 1 || function(current) != strings.Replace(previous, old, new, 1) {
		t.Fatal("dispatch changed other operation audit authority")
	}
	_, down, ok := strings.Cut(current, "-- +goose Down")
	restore := strings.Index(down, "-- +goose StatementBegin\nCREATE OR REPLACE FUNCTION guard_operation_audit()")
	if !ok || restore < 0 || function(down[restore:]) != previous {
		t.Fatal("downgrade did not restore exact prior guard")
	}
}

func TestRecordingSaveDispatchDowngradeProtectsOnlyRetainedLongRequests(t *testing.T) {
	raw, err := fs.ReadFile(migrations.Files(), "00111_recording_save_dispatch_window.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, down, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("missing downgrade")
	}
	predicate := `SELECT 1 FROM public.operation_audit WHERE intent->>'Name'='request_capture' AND request_until>(intent->>'CreatedAt')::timestamptz+interval '5 seconds'`
	guard := strings.Index(down, predicate)
	restore := strings.Index(down, "CREATE OR REPLACE FUNCTION guard_operation_audit()")
	lock := strings.Index(down, "LOCK TABLE public.operation_audit IN SHARE MODE;")
	if guard < 0 || restore < 0 || guard >= restore || lock < 0 || lock >= guard {
		t.Fatal("downgrade can strand retained long-window requests before old guard restoration")
	}
	if !strings.Contains(down, "RAISE EXCEPTION 'retained long-window capture requests cannot downgrade' USING ERRCODE='23514'") {
		t.Fatal("downgrade refusal lacks closed protocol classification")
	}
	// Real typed format validation shows why the new records cannot be handed to
	// old readers. Expiry does not make a retained intent old-format compatible.
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		window  time.Duration
		blocked bool
	}{{"request_capture", 5 * time.Second, false}, {"request_capture", 5*time.Second + time.Microsecond, true}, {"request_capture", 15 * time.Second, true}, {"get_query_result", 20 * time.Second, false}, {"get_capture", 5 * time.Second, false}} {
		id := "00000000-0000-4000-8000-000000000001"
		in := audit.OperationIntent{ID: id, RootID: id, TraceID: id, Name: tc.name, InputFormat: "context-input/v1", MACVersion: "mac-v1", AccountVersion: "accounts-v1", Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: now, RequestUntil: now.Add(tc.window), WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
		if tc.name == "get_query_result" {
			in.InputFormat = "context-query-input/v1"
		}
		if !in.Valid() {
			t.Fatalf("invalid current format baseline %s %v", tc.name, tc.window)
		}
		oldWindow := 5 * time.Second
		if tc.name == "get_query_result" {
			oldWindow = identity.EvidenceReadRequestWindow
		}
		oldReadable := identity.Fresh(in.CreatedAt, in.RequestUntil, in.CreatedAt, oldWindow)
		if oldReadable == tc.blocked {
			t.Fatalf("old reader compatibility mismatch %s/%v", tc.name, tc.window)
		}
	}
}
