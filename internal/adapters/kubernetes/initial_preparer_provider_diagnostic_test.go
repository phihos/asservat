package kubernetes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestInitialProviderPreparationDiagnosticSeparatesOriginalDeadlines(t *testing.T) {
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	secret := errors.New("DO-NOT-LEAK-token-provider-response")
	for _, test := range []struct {
		name           string
		parent, active time.Time
		elapsed        time.Duration
		want           string
	}{
		{"operation-expired", n.Add(40 * time.Second), n.Add(5 * time.Second), 6 * time.Second, "elapsed_ms=6000 parent_start_ms=40000 parent_remaining_ms=34000 original_operation_remaining_ms=0"},
		{"process-expired", n.Add(3 * time.Second), n.Add(3 * time.Second), 4 * time.Second, "elapsed_ms=4000 parent_start_ms=3000 parent_remaining_ms=0 original_operation_remaining_ms=0"},
		{"bounded-unknown", time.Time{}, time.Time{}, 2 * time.Hour, "elapsed_ms=60000 parent_start_ms=-1 parent_remaining_ms=-1 original_operation_remaining_ms=-1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := initialPreparationProviderFailure{phase: "provider-issue", cause: secret, started: n, finished: n.Add(test.elapsed), parentUntil: test.parent, activeUntil: test.active}
			got := InitialPreparationProviderDiagnostic(e)
			if !errors.Is(e, secret) || strings.Contains(e.Error(), secret.Error()) || got != "phase=provider-issue "+test.want {
				t.Fatal("unsafe or unbounded original deadline diagnostic", got)
			}
		})
	}
	if InitialPreparationProviderDiagnostic(initialPreparationProviderFailure{phase: secret.Error(), cause: secret}) != "" {
		t.Fatal("unqualified phase rendered")
	}
	var b *InitialPreparationCredentialBinder
	_, _, e := b.PrepareProvider(context.Background(), "wrap", nil)
	if !errors.Is(e, cfg.ErrInvalid) || !strings.Contains(InitialPreparationProviderDiagnostic(e), "phase=inputs ") {
		t.Fatal("entry phase missing", e)
	}
}
