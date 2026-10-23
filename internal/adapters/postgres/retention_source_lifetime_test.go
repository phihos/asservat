package postgres

import (
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/privacy"
)

// ADR-200 revision (2026-10-23): migration 00075 lets an accepted retention
// source observation live 30 seconds after its own observation and Down
// restores the five-second rule. Invalidation, suspension and takeover still
// clear the stored observation at once.
func TestRetentionSourceThirtySecondLifetime(t *testing.T) {
	observed := time.Date(2026, 10, 23, 12, 0, 0, 123456789, time.UTC)
	if got := retentionSourceUntil(observed); !got.Equal(observed.Truncate(time.Microsecond).Add(30*time.Second)) || privacy.RetentionSourceInterval != 30*time.Second {
		t.Fatalf("stored retention source lifetime %s", got.Sub(observed))
	}
	b, err := os.ReadFile("../../../migrations/00075_retention_source_freshness.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok || !strings.Contains(up, "fresh_until<=observed_at+interval '30 seconds'") || strings.Contains(up, "'5 seconds'") {
		t.Fatal("Up does not widen only the retention observation bound")
	}
	for _, want := range []string{
		"UPDATE retention_source SET fresh_until=observed_at+interval '5 seconds'",
		"fresh_until<=observed_at+interval '5 seconds'",
	} {
		if !strings.Contains(down, want) {
			t.Fatalf("Down lacks %q", want)
		}
	}
	q, err := os.ReadFile("../../../migrations/queries/retention_sources.sql")
	if err != nil {
		t.Fatal(err)
	}
	queries := string(q)
	for _, name := range []string{"StartRetentionSource", "SuspendRetentionSource", "InvalidateRetentionObservation"} {
		_, rest, _ := strings.Cut(queries, "-- name: "+name+" ")
		statement, _, _ := strings.Cut(rest, ";")
		if !strings.Contains(statement, "observed_at=NULL,fresh_until=NULL") {
			t.Fatalf("%s no longer clears the observation at once", name)
		}
	}
	if !strings.Contains(queries, "fresh_until=$5,lease_until=GREATEST(lease_until,$5)") {
		t.Fatal("observation does not keep the lease for its lifetime")
	}
}
