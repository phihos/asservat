package bootstrap

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

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

type timedOpeningDiagnostic struct {
	step               string
	elapsed, remaining time.Duration
}

func (d timedOpeningDiagnostic) Error() string     { panic("reporter inspected dependency text") }
func (d timedOpeningDiagnostic) Unwrap() error     { return fleet.ErrDenied }
func (d timedOpeningDiagnostic) FixedStep() string { return d.step }
func (d timedOpeningDiagnostic) OpeningTiming() (time.Duration, time.Duration) {
	return d.elapsed, d.remaining
}

func TestRegionalContextOpeningTimingDoesNotExpandRateLimitKey(t *testing.T) {
	var out bytes.Buffer
	s := RegionalContextStartConnections{Report: eventLog(&out, "regional context standby refused"), ReportOpening: contextStartOpeningLog(&out)}
	for n := 1; n <= 32; n++ {
		s.reportFailure("open", timedOpeningDiagnostic{"owner-first", time.Duration(n) * time.Millisecond, time.Second - time.Duration(n)*time.Millisecond})
	}
	if strings.Count(out.String(), "open/owner-first (denied)") != 6 || !strings.Contains(out.String(), "elapsed=") || !strings.Contains(out.String(), "remaining=") {
		t.Fatalf("timings changed suppression: %s", out.String())
	}
	s.reportFailure("open", timedOpeningDiagnostic{"private-token-host", time.Second, time.Second})
	s.reportFailure("open", timedOpeningDiagnostic{"setup-source-close", time.Second, time.Second})
	s.reportFailure("open", timedOpeningDiagnostic{"setup-fresh", time.Second, time.Second})
	s.reportFailure("open", timedOpeningDiagnostic{"tls", time.Second, 10 * time.Second})
	if strings.Contains(out.String(), "private-") || !strings.Contains(out.String(), "open/setup-source-close") || !strings.Contains(out.String(), "open/setup-fresh") || strings.Contains(out.String(), "remaining=10s") {
		t.Fatalf("diagnostic leaked unknown values: %s", out.String())
	}
}
