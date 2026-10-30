package postgres

import (
	"asservat.local/asservat/migrations"
	"io/fs"
	"strings"
	"testing"
)

// Definition comparison is a pure migration guard. Actual trigger execution
// remains part of the owned real-SQL source107 publication qualification.
func TestSnapshotProcessingMigrationPreservesExistingFiniteFunction(t *testing.T) {
	function := func(name string, up bool) string {
		t.Helper()
		raw, err := fs.ReadFile(migrations.Files(), name)
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		cut := strings.Index(s, "-- +goose Down")
		if cut >= 0 {
			if up {
				s = s[:cut]
			} else {
				s = s[cut:]
			}
		}
		start := strings.Index(s, "CREATE OR REPLACE FUNCTION project_context_processing()")
		if start < 0 {
			t.Fatal("processing function missing", name)
		}
		s = s[start:]
		end := strings.Index(s, "-- +goose StatementEnd")
		if end < 0 {
			t.Fatal("unbounded processing definition", name)
		}
		return s[:end]
	}
	prior := function("00098_manual_packet_recording.sql", true)
	current := function("00106_source_snapshot_completions.sql", true)
	addition := " OR\n    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='pcapng' AND jsonb_typeof(e->'Snapshot')='object' AND (NOT e ? 'Recording' OR e->'Recording'='null'::jsonb)"
	if strings.Count(current, addition) != 1 || strings.Replace(current, addition, "", 1) != prior {
		t.Fatal("snapshot alternative changed finite processing predicates or accounting")
	}
	if function("00106_source_snapshot_completions.sql", false) != prior {
		t.Fatal("downgrade does not restore original finite lineage")
	}
}
