package postgres

import (
	"asservat.local/asservat/migrations"
	"io/fs"
	"strings"
	"testing"
)

func TestArgumentProcessingMigrationPreservesProfilesAndExactDown(t *testing.T) {
	function := func(name string, up bool) string {
		t.Helper()
		raw, err := fs.ReadFile(migrations.Files(), name)
		if err != nil {
			t.Fatal(err)
		}
		before, after, ok := strings.Cut(string(raw), "-- +goose Down")
		if !ok {
			t.Fatal("missing Down", name)
		}
		s := before
		if !up {
			s = after
		}
		start := strings.Index(s, "CREATE OR REPLACE FUNCTION project_context_processing()")
		if start < 0 {
			t.Fatal("missing function", name)
		}
		s = s[start:]
		end := strings.Index(s, "-- +goose StatementEnd")
		if end < 0 {
			t.Fatal("missing function boundary", name)
		}
		return s[:end]
	}
	old := function("00123_profile_acquisition.sql", true)
	current := function("00129_syscall_arguments_processing.sql", true)
	addition := " OR e->>'NativeType'='syscallArguments' AND e#>>'{Recording,Kind}'='syscallTrace' AND e#>>'{Recording,Profile}'='arguments' AND jsonb_typeof(e#>'{Recording,Arguments}')='object' AND NOT e ? 'Snapshot' AND NOT e ? 'Profile' AND NOT e ? 'Lifecycle'"
	if strings.Count(current, addition) != 1 {
		t.Fatal("missing exact argument recording branch")
	}
	restored := strings.Replace(current, addition, "", 1)
	restored = strings.Replace(restored, " AND e->>'NativeType' IS DISTINCT FROM 'syscallArguments'", "", 1)
	restored = strings.Replace(restored, "IN ('rawPcapng','pprof','goTrace','syscallArguments')", "IN ('rawPcapng','pprof','goTrace')", 1)
	if restored != old {
		t.Fatal("argument processing altered existing profile/metadata lineage or accounting")
	}
	if function("00129_syscall_arguments_processing.sql", false) != old {
		t.Fatal("Down did not restore exact qualified profile function")
	}
}
