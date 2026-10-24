package native

import "errors"

// nativeStep labels a refused native admission or conversation with its
// closed stage for the operator report (ADR-197). It unwraps to the returned
// error unchanged, so no caller decision changes, and never carries text,
// identifiers or evidence.
type nativeStep struct {
	step string
	err  error
}

func (e *nativeStep) Error() string { return e.err.Error() }
func (e *nativeStep) Unwrap() error { return e.err }
func (e *nativeStep) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}

// step labels err with its stage; nil stays nil.
func step(name string, err error) error {
	if err == nil {
		return nil
	}
	return &nativeStep{name, err}
}
