package kubernetes

import (
	"errors"
	"strings"
	"testing"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

type fixedSQLStep struct{ error }

func (fixedSQLStep) FixedStep() string { return "owner projection SQL: finalize-final-read" }

// The intermittent launch failures (runs 35, 41, 46, 48) rendered no step:
// the stop text now names the current-read cause and the SQL facet's step,
// while errors.Is still sees the original class.
func TestOwnerProjectionCurrentFailureRendersClosedCodes(t *testing.T) {
	current := ownerOperationError(ownerCurrentAcceptedValid, cfg.ErrUnavailable)
	slot := projectionFixedCodes(projectionDiagnostic(projectionCheckCurrentNative, current))
	outer := projectionDiagnostic(projectionCheckFinalNative, fixedSQLStep{cfg.ErrUnavailable})
	outer.detail = "unavailable after 1s; owner projection SQL: finalize-final-read"
	outer.inner = slot
	text := outer.Error()
	for _, want := range []string{"projection.final-native", "finalize-final-read", "projection.current-native", "current.accepted-valid"} {
		if !strings.Contains(text, want) {
			t.Fatalf("stop text %q lacks %q", text, want)
		}
	}
	if !errors.Is(current, cfg.ErrUnavailable) || ownerOperationError(ownerCurrentDeployment, cfg.ErrChanged) == nil || !errors.Is(configurationSourceError(configurationSourceCurrentDeployment, cfg.ErrChanged), cfg.ErrChanged) {
		t.Fatal("closed codes hid the original class")
	}
	if ownerCurrentDeadline.String() != "current.deadline" || configurationSourceCurrentDeadline.String() != "source.current-deadline" {
		t.Fatal("new closed codes unnamed")
	}
}
