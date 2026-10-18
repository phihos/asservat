package bootstrap

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	fleet "asservat.local/asservat/internal/domain/fleet"
)

func TestRegionalContextDiagnosticsKeepClosedVocabulary(t *testing.T) {
	var out bytes.Buffer
	s := RegionalContextStartConnections{Report: eventLog(&out, "regional context standby refused")}
	private := fmt.Errorf("private-token-host-workload: %w", fleet.ErrDenied)
	wrapped := &fixedStepError{"private-token-host-workload", private}
	for range 8 {
		s.reportFailure("open", wrapped)
	}
	s.reportFailure("candidates", nil)
	s.reportFailure("candidates-empty", nil)
	s.reportFailure("exchange", &fixedStepError{"peer", private})
	s.reportFailure("private-token-host-workload", private)
	if !errors.Is(wrapped, fleet.ErrDenied) || strings.Contains(out.String(), "private-") || strings.Count(out.String(), "open (denied)") != 4 || !strings.Contains(out.String(), "exchange/peer (denied)") || !strings.Contains(out.String(), "candidates-empty") {
		t.Fatalf("unsafe or unbounded diagnostic: %s", out.String())
	}
}

type forbiddenDiagnosticInspection struct{}

func (forbiddenDiagnosticInspection) Error() string { panic("reporter inspected private error text") }
func (forbiddenDiagnosticInspection) FixedStep() string {
	panic("missing reporter inspected dependency")
}

func TestRegionalContextMissingReporterDoesNoWork(t *testing.T) {
	RegionalContextStartConnections{}.reportFailure("open", forbiddenDiagnosticInspection{})
}
