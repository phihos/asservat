package postgres

import (
	"os"
	"strings"
	"testing"
)

// The prior WIP copied schema82 and silently removed later public operations.
// Keep108's changes restricted to its three new operation names.
func TestRecordingSaveAuditRegistrationPreservesLatestOperationUnion(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile("../../../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	old := strings.Split(read("00102_policy_grants.sql"), "-- +goose Down")[0]
	migration := read("00108_recording_save_control.sql")
	halves := strings.SplitN(migration, "-- +goose Down", 2)
	extract := func(s, name string) string {
		t.Helper()
		start := strings.Index(s, "CREATE OR REPLACE FUNCTION "+name+"(")
		if start < 0 {
			t.Fatal("missing function", name)
		}
		tail := s[start:]
		end := strings.Index(tail, "$$;")
		if end < 0 {
			t.Fatal("unterminated", name)
		}
		return strings.Join(strings.Fields(tail[:end+3]), " ")
	}
	for _, name := range []string{"operation_audit_lane", "operation_audit_human_input_valid"} {
		baseline := extract(old, name)
		up := extract(halves[0], name)
		for _, added := range []string{"list_recordings", "preview_recording_save", "cancel_capture"} {
			if strings.Count(up, "'"+added+"'") != 1 {
				t.Fatal("new operation missing or duplicated", name, added)
			}
			up = strings.ReplaceAll(up, "'"+added+"',", "")
		}
		if up != baseline {
			t.Fatal("unrelated operation registration changed", name)
		}
		if extract(halves[1], name) != baseline {
			t.Fatal("downgrade did not restore original operations", name)
		}
	}
}
