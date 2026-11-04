package bootstrap

import (
	"errors"
	"fmt"
	"time"
)

// Operator metadata only: all actual deadline/context expressions remain in
// the observation owner. Ties keep the first original source's label.
type observationCutoff struct {
	label string
	until time.Time
}

func (d *observationCutoff) narrow(label string, until time.Time) {
	if until.Before(d.until) {
		d.label, d.until = label, until
	}
}

type observationCutoffFailure struct {
	err            error
	cutoff         observationCutoff
	finalRemaining time.Duration
	finalAttempted bool
}

func (e *observationCutoffFailure) Error() string { return e.err.Error() }
func (e *observationCutoffFailure) Unwrap() error { return e.err }
func (e *observationCutoffFailure) ObservationDeadlineDiagnostic() (string, time.Time, time.Duration) {
	return e.cutoff.label, e.cutoff.until, e.finalRemaining
}

// Called only by the existing private failure log. Never render provider text,
// target/credential identifiers or arbitrary method-supplied labels.
func observationFailureDetail(err error) string {
	detail := ""
	var d *observationCutoffFailure
	if errors.As(err, &d) {
		switch d.cutoff.label {
		case "caller", "candidates", "route", "firstregistry", "registry-current", "nativefacts", "locator":
			detail = fmt.Sprintf(" until-authority/%s=%s", d.cutoff.label, d.cutoff.until.UTC().Format(time.RFC3339Nano))
			if d.finalAttempted {
				detail += fmt.Sprintf(" final_remaining_ms=%d", d.finalRemaining.Milliseconds())
			}
		}
	}
	var probe interface {
		ProbeFailureDiagnostic() (string, time.Duration)
	}
	if errors.As(err, &probe) {
		category, remaining := probe.ProbeFailureDiagnostic()
		switch category {
		case "deadline", "canceled", "body", "transport":
			detail += fmt.Sprintf(" probe=%s probe_remaining_ms=%d", category, remaining.Milliseconds())
		}
	}
	return detail
}
