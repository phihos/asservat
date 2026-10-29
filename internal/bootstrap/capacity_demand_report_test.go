package bootstrap

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestCapacityDemandReporterDoesNotInventReadProofBudget(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	defer func() { os.Stderr = original; _ = writer.Close(); _ = reader.Close() }()
	os.Stderr = writer
	report := capacityDemandReporter()
	for _, stage := range []string{"read", "read-deadline", "cluster-unmatched"} {
		report(cfg.ErrUnavailable, 10*time.Millisecond, 0, stage)
	}
	report(nil, 20*time.Millisecond, 250*time.Millisecond, "guarded-read=10ms guarded-reconcile=10ms")
	report(cfg.ErrUnavailable, 20*time.Millisecond, 0, "guarded-read=20ms")
	os.Stderr = original
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 5 {
		t.Fatal("unexpected report count", len(lines))
	}
	for i := range 3 {
		if !strings.Contains(lines[i], "read left not-applicable [") {
			t.Fatal("pre-candidate placeholder looked like measured proof expiry", lines[i])
		}
	}
	if !strings.Contains(lines[3], "read left 250ms [") || !strings.Contains(lines[4], "read left 0s [") {
		t.Fatal("real guarded-read budgets changed", lines[3:])
	}
}
