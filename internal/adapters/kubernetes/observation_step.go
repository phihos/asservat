package kubernetes

import "errors"

// observationStep names the fixed metadata check that refused, for operator
// diagnostics (FixedStep); it wraps the original error.
type observationStep struct {
	step string
	err  error
}

func (e *observationStep) Error() string { return e.step }
func (e *observationStep) Unwrap() error { return e.err }

// FixedStep appends a nested fixed step, so labels compose across layers.
func (e *observationStep) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}
