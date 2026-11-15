package mtls

import (
	"context"
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
