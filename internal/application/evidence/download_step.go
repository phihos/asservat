package evidence

import (
	"context"
	"errors"
)

// downloadStep names the closed native-download preparation stage that
// refused, for the operator report (ADR-197). It unwraps to the returned error
// unchanged, so no caller decision changes. A collapsed dependency error is
// retained only as StepCause, for its closed class; it is never unwrapped.
type downloadStep struct {
	step       string
	err, cause error
}

func (e *downloadStep) Error() string { return e.err.Error() }
func (e *downloadStep) Unwrap() error { return e.err }

// StepCause is the innermost retained dependency cause, if any.
func (e *downloadStep) StepCause() error {
	if e.cause != nil {
		return e.cause
	}
	var inner interface{ StepCause() error }
	if errors.As(e.err, &inner) {
		return inner.StepCause()
	}
	return nil
}
func (e *downloadStep) FixedStep() string {
	var inner interface{ FixedStep() string }
	if e.cause != nil && errors.As(e.cause, &inner) || errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}

// stepped labels a returned error with its stage; nil stays nil.
func stepped(step string, err error) error {
	if err == nil {
		return nil
	}
	return &downloadStep{step: step, err: err}
}

// collapsed returns err labelled with its stage, retaining the dependency cause
// that the stage replaced by err.
func collapsed(step string, err, cause error) error {
	return &downloadStep{step: step, err: err, cause: cause}
}

// refused reports a refused coordinator operation once, at its boundary.
func (s ContextDownloadCoordinator) refused(ctx context.Context, operation string, err error) {
	if err != nil && s.Refused != nil {
		s.Refused(ctx, operation, err)
	}
}
