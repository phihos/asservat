package bootstrap

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Untrusted method strings never enter the private log, and absent final
// attempts cannot be presented as having a measured zero remaining interval.
type arbitraryProbeDiagnostic struct{}

func (arbitraryProbeDiagnostic) Error() string { return "private-provider-text" }
func (arbitraryProbeDiagnostic) ProbeFailureDiagnostic() (string, time.Duration) {
	return "private-provider-token", time.Hour
}
func TestDirectHolderFailureDiagnosticClosedLabels(t *testing.T) {
	err := &observationCutoffFailure{err: arbitraryProbeDiagnostic{}, cutoff: observationCutoff{label: "private-provider-label", until: time.Now()}}
	if got := observationFailureDetail(err); got != "" {
		t.Fatal("private text rendered", got)
	}
	err.cutoff.label = "caller"
	got := observationFailureDetail(err)
	if !strings.Contains(got, "until-authority/caller=") || strings.Contains(got, "final_remaining") || strings.Contains(got, "private") {
		t.Fatal("incorrect cutoff-only diagnostic", got)
	}
}

// Exact timestamps improve each reported failure without changing the
// observation adapter's original per-category suppression of repeated logs.
func TestDirectHolderFailureDiagnosticKeepsStableCategory(t *testing.T) {
	first := &fixedStepError{"native-final", &observationCutoffFailure{err: errors.New("private"), cutoff: observationCutoff{label: "caller", until: time.Now()}}}
	second := &fixedStepError{"native-final", &observationCutoffFailure{err: errors.New("private"), cutoff: observationCutoff{label: "locator", until: time.Now().Add(time.Second)}}}
	if regionalOutcomeClass(first) != regionalOutcomeClass(second) || regionalOutcome(first) == regionalOutcome(second) {
		t.Fatal("dynamic deadline affected suppression key or disappeared")
	}
}
