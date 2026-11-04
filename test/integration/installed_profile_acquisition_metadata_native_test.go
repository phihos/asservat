package integration

import (
	"asservat.local/asservat/internal/transport/presentation"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"
)

// Read back the already persisted verification metadata, never a raw manifest or
// a key. This comparison supplies no capture, disclosure or clock authority.
func qualifyInstalledProfileAcquisitionMetadata(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root, captureID string, a presentation.ContextCaseArtifactData) {
	t.Helper()
	p := a.ProfileAcquisition
	if p == nil || p.RequestedType != "cpu" || p.Mode != "interval" || p.RequestedDurationMillis == nil || *p.RequestedDurationMillis != 10000 || p.ForceGC || p.ExecutionMode != "onTrigger" || p.WindowKind != "httpAcquisition" || p.TimestampPrecision != "microsecond" || p.ClockUncertaintyMillis != nil || p.ProcessAttribution != "unknown" || p.StartedAt == nil || p.CompletedAt == nil {
		t.Fatal("profile case lost verified acquisition parameters/unknown facts", p)
	}
	if p.StartedAt.IsZero() || p.CompletedAt.IsZero() || p.CompletedAt.Before(*p.StartedAt) || p.StartedAt.Nanosecond()%1000 != 0 || p.CompletedAt.Nanosecond()%1000 != 0 {
		t.Fatal("profile case acquisition interval is invalid or has unexpected precision")
	}
	var start, end time.Time
	if err := admin.QueryRow(ctx, `SELECT acquisition_started_at,acquisition_completed_at FROM context_verification WHERE root_id=$1 AND capture_id=$2`, root, captureID).Scan(&start, &end); err != nil || !start.Equal(*p.StartedAt) || !end.Equal(*p.CompletedAt) {
		t.Fatal("public acquisition interval differs from verified SQL metadata", err)
	}
	t.Logf("installed profile case: HTTP acquisition %s to %s, UTC microsecond display precision; incident/clock uncertainty/serving process remain unknown", start.UTC().Format(time.RFC3339Nano), end.UTC().Format(time.RFC3339Nano))
}
