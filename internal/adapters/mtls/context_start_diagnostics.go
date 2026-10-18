package mtls

import (
	"context"
	"errors"
	"strings"
	"time"
)

// This state is private to one opening and observes its existing bounds only.
// Its wall-clock measurements never drive authority or cancellation. Dependency
// text, identities, addresses and payloads cannot enter the diagnostic.
type contextStartOpeningDiagnostic struct {
	stage          string
	started, until time.Time
	trace          string // setup marks only: fixed step names and durations
}

func newContextStartOpeningDiagnostic(ctx context.Context, until time.Time) *contextStartOpeningDiagnostic {
	if ctx != nil {
		if end, ok := ctx.Deadline(); ok && (until.IsZero() || end.Before(until)) {
			until = end
		}
	}
	return &contextStartOpeningDiagnostic{stage: "discovery", started: time.Now(), until: until}
}

func (d *contextStartOpeningDiagnostic) at(stage string) {
	if d != nil {
		d.stage = stage
	}
}
func (d *contextStartOpeningDiagnostic) bound(until time.Time) {
	if d != nil && !until.IsZero() && (d.until.IsZero() || until.Before(d.until)) {
		d.until = until
	}
}

// setupStep accepts only a closed producer code, never its older FixedStep
// trace (which contains elapsed marks), an Error string or arbitrary labels.
func (d *contextStartOpeningDiagnostic) setupStep(err error) {
	var step interface {
		ContextStartSetupStep() string
		ContextStartSetupUntil() time.Time
	}
	if errors.As(err, &step) {
		switch s := step.ContextStartSetupStep(); s {
		case "source-open", "owned-process", "process-proof", "process-match", "execution-account", "settings-guard", "settings-snapshot", "workload", "settings-guard-after", "settings-snapshot-after", "workload-guard-after", "source-close", "owned-process-after", "fresh":
			d.stage = "setup-" + s
			d.bound(step.ContextStartSetupUntil())
			d.trace = setupMarks(err)
		}
	}
}

// setupMarks keeps only the completed-check marks of the setup proof's trace
// ("name@duration ..."), which its producer builds from fixed names and
// durations, restricted to that alphabet and length.
func setupMarks(err error) string {
	var fixed interface{ FixedStep() string }
	if !errors.As(err, &fixed) {
		return ""
	}
	trace := fixed.FixedStep()
	i := strings.Index(trace, " after [")
	if i < 0 {
		return ""
	}
	marks, _, ok := strings.Cut(trace[i+len(" after ["):], "]")
	if !ok || len(marks) > 512 {
		return ""
	}
	for _, r := range marks {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("@.- µ", r)) {
			return ""
		}
	}
	return marks
}

func (d *contextStartOpeningDiagnostic) wrap(err error) error {
	if err == nil {
		return nil
	}
	now := time.Now()
	elapsed, remaining := now.Sub(d.started), d.until.Sub(now)
	if elapsed < 0 {
		elapsed = 0
	}
	if remaining < 0 {
		remaining = 0
	}
	return &contextStartOpeningError{cause: err, stage: d.stage, elapsed: elapsed, remaining: remaining, trace: d.trace}
}

type contextStartOpeningError struct {
	cause              error
	stage              string
	elapsed, remaining time.Duration
	trace              string
}

func (e *contextStartOpeningError) Error() string     { return "context start opening refused" }
func (e *contextStartOpeningError) Unwrap() error     { return e.cause }
func (e *contextStartOpeningError) FixedStep() string { return e.stage }
func (e *contextStartOpeningError) OpeningTiming() (time.Duration, time.Duration) {
	return e.elapsed, e.remaining
}
func (e *contextStartOpeningError) OpeningTrace() string { return e.trace }
