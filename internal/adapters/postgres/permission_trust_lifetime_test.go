package postgres

import (
	"io/fs"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/migrations"
)

// ADR-200 revision (2026-10-23): the permission stream lives 30 seconds after
// its own observation, in Go and in the stored CHECK.
func TestPermissionTrustThirtySecondLifetime(t *testing.T) {
	observed := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	if got := permissionStreamUntil(observed); !got.Equal(observed.Add(30 * time.Second)) {
		t.Fatalf("stored permission stream lifetime %s", got.Sub(observed))
	}
	b, err := fs.ReadFile(migrations.Files(), "00001_baseline.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "CONSTRAINT permission_stream_observation_lifetime CHECK (((fresh_until IS NULL) OR ((fresh_until > observed_at) AND (fresh_until <= (observed_at + '00:00:30'::interval)))))") {
		t.Fatal("permission stream CHECK is not 30 seconds")
	}
	if authorization.PermissionObservationInterval != 30*time.Second {
		t.Fatal("permission observation interval differs from the stored lifetime")
	}
}
