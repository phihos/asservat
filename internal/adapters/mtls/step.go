package mtls

import (
	"errors"
)

// answerStep labels a refusal with its fixed step; the result still matches
// sentinel, and cause (when set) for any nested step and closed cause.
func answerStep(step string, sentinel, cause error) error {
	return &operationStep{step, errors.Join(sentinel, cause)}
}

// operationStep names the fixed step at which an operation was refused, for
// operator diagnostics (FixedStep); it wraps the original error.
type operationStep struct {
	step string
	err  error
}

func (e *operationStep) Error() string { return e.step }
func (e *operationStep) Unwrap() error { return e.err }

// FixedStep appends a nested fixed step, so labels compose across layers.
func (e *operationStep) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}
