package postgres

import (
	"io/fs"
	"strings"
	"testing"

	"asservat.local/asservat/migrations"
)

// Migration 00145 only relaxes the start binding bound to the ADR-311
// interval; Down restores 00035's exact five-second bound and refuses while a
// wider binding is retained.
func TestAPIStartIntervalMigrationRestoresFiveSeconds(t *testing.T) {
	body, err := fs.ReadFile(migrations.Files(), "00145_api_start_recheck_interval.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(body), "-- +goose Down")
	if !ok {
		t.Fatal("missing Down")
	}
	original, err := fs.ReadFile(migrations.Files(), "00035_api_context_execution.sql")
	if err != nil {
		t.Fatal(err)
	}
	const five = "CHECK(isfinite(not_after) AND not_after>not_before AND not_after<=not_before+interval '5 seconds')"
	if !strings.Contains(string(original), five) {
		t.Fatal("00035 bound changed")
	}
	if !strings.Contains(up, "CHECK(isfinite(not_after) AND not_after>not_before AND not_after<=not_before+interval '30 seconds')") || !strings.Contains(down, five) {
		t.Fatal("bound is not exactly 30 s up and 5 s down")
	}
	refusal, restore, _ := strings.Cut(down, "ALTER TABLE")
	if !strings.Contains(refusal, "not_after>not_before+interval '5 seconds'") || !strings.Contains(refusal, "RAISE EXCEPTION") || restore == "" {
		t.Fatal("Down does not refuse retained wider bindings before restoring")
	}
	for _, s := range []string{"CREATE TABLE", "GRANT ", "ADD COLUMN", "FUNCTION"} {
		if strings.Contains(up, s) {
			t.Fatal("relaxation added state, privileges or functions:", s)
		}
	}
}
