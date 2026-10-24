package postgres

import (
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
)

// ADR-200 revision (2026-10-23): migration 00074 lets the permission stream
// and the positive fleet trust observation live 30 seconds after their own
// observation, and Down restores the five-second rule.
func TestPermissionTrustThirtySecondLifetime(t *testing.T) {
	observed := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	if got := permissionStreamUntil(observed); !got.Equal(observed.Add(30 * time.Second)) {
		t.Fatalf("stored permission stream lifetime %s", got.Sub(observed))
	}
	b, err := os.ReadFile("../../../migrations/00074_permission_trust_freshness.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("missing Down section")
	}
	for _, want := range []string{
		"fresh_until<=observed_at+interval '30 seconds'",
		"'p.fresh_until<=p.observed_at+interval ''5 seconds''','p.fresh_until<=p.observed_at+interval ''30 seconds'''",
		"'stream.fresh_until>stream.observed_at+interval ''5 seconds''','stream.fresh_until>stream.observed_at+interval ''30 seconds'''",
		"'observed_at=observed,fresh_until=fresh WHERE installation_id=i;','observed_at=observed,fresh_until=observed+interval ''30 seconds'' WHERE installation_id=i;'",
	} {
		if !strings.Contains(up, want) {
			t.Fatalf("Up lacks %q", want)
		}
	}
	// Four permission bounds and the one positive fleet row; nothing else.
	if n := strings.Count(up, "''30 seconds''"); n != 5 {
		t.Fatalf("Up rewrites %d bounds", n)
	}
	for _, want := range []string{
		"fresh_until<=observed_at+interval '5 seconds'",
		"'observed_at=observed,fresh_until=observed+interval ''30 seconds'' WHERE installation_id=i;','observed_at=observed,fresh_until=fresh WHERE installation_id=i;'",
		"UPDATE permission_stream SET fresh_until=observed_at+interval '5 seconds'",
		"UPDATE fleet_observation SET fresh_until=observed_at+interval '5 seconds'",
	} {
		if !strings.Contains(down, want) {
			t.Fatalf("Down lacks %q", want)
		}
	}
	if authorization.PermissionObservationInterval != 30*time.Second {
		t.Fatal("permission observation interval differs from the stored lifetime")
	}
}
