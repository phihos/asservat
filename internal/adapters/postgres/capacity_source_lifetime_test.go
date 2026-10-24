package postgres

import (
	"os"
	"strings"
	"testing"
)

// ADR-200 revision (2026-10-23): migration 00073 stores an accepted root
// capacity source for 30 seconds after its own observation, the table accepts
// at most 30 seconds, and Down restores the five-second rule. The caller's
// receipt keeps its original interval, which AcceptCapacitySource still checks
// against app.CapacitySourceInterval.
func TestCapacitySourceThirtySecondLifetime(t *testing.T) {
	b, err := os.ReadFile("../../../migrations/00073_capacity_source_freshness.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("missing Down section")
	}
	for _, want := range []string{
		"fresh_until=observed+interval '30 seconds',suspended=false",
		"fresh_until<=observed_at+interval '30 seconds'",
		"'FreshUntil',until_at",
	} {
		if !strings.Contains(up, want) {
			t.Fatalf("Up lacks %q", want)
		}
	}
	// Negative and invalidating observations keep their original intervals.
	if strings.Count(up, "observed+interval '30 seconds'") != 1 {
		t.Fatal("30-second lifetime must apply only to accepted observations")
	}
	for _, want := range []string{
		"fresh_until=until_at,suspended=false",
		"fresh_until<=observed_at+interval '5 seconds'",
	} {
		if !strings.Contains(down, want) {
			t.Fatalf("Down lacks %q", want)
		}
	}
	if strings.Contains(down, "observed+interval '30 seconds'") {
		t.Fatal("Down keeps the 30-second producer")
	}
}
