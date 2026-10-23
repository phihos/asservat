package analysis

import (
	"context"
	"errors"
)

// queryStep names the closed approved-query stage that refused, for the
// operator report (like the native-download stages). It unwraps to the returned
// error unchanged, so no caller decision changes. A collapsed dependency error
// is retained only as StepCause, for its closed class; it is never unwrapped.
type queryStep struct {
	step       string
	err, cause error
}

func (e *queryStep) Error() string { return e.err.Error() }
func (e *queryStep) Unwrap() error { return e.err }

// StepCause is the innermost retained dependency cause, if any.
func (e *queryStep) StepCause() error {
	var inner interface{ StepCause() error }
	if e.cause != nil {
		if errors.As(e.cause, &inner) && inner.StepCause() != nil {
			return inner.StepCause()
		}
		return e.cause
	}
	if errors.As(e.err, &inner) {
		return inner.StepCause()
	}
	return nil
}
func (e *queryStep) FixedStep() string {
	var inner interface{ FixedStep() string }
	if e.cause != nil && errors.As(e.cause, &inner) || errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}

// queryStepped labels a returned error with its stage; nil stays nil.
func queryStepped(step string, err error) error {
	if err == nil {
		return nil
	}
	return &queryStep{step: step, err: err}
}

// queryCollapsed returns err labelled with its stage, retaining the dependency
// cause (possibly nil) that the stage replaced by err.
func queryCollapsed(step string, err, cause error) error {
	return &queryStep{step: step, err: err, cause: cause}
}

// refused reports a refused approved query once, at its service boundary.
func (s ContextProjectionResults) refused(ctx context.Context, operation string, err error) {
	if err != nil && s.Refused != nil {
		s.Refused(ctx, operation, err)
	}
}
