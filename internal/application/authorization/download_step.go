package authorization

import (
	"errors"

	"asservat.local/asservat/internal/domain/artifact"
)

// authorityCheckStep names the closed authority stage that refused, for
// the operator report (ADR-197). It unwraps to the returned sentinel only, so
// no caller decision changes; the dependency cause is retained for its class.
type authorityCheckStep struct {
	step       string
	err, cause error
}

func (e *authorityCheckStep) Error() string { return e.err.Error() }
func (e *authorityCheckStep) Unwrap() error { return e.err }
func (e *authorityCheckStep) StepCause() error {
	return e.cause
}
func (e *authorityCheckStep) FixedStep() string {
	var inner interface{ FixedStep() string }
	if e.cause != nil && errors.As(e.cause, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}

// downloadRefused returns ErrDownloadUnavailable labelled with its stage.
func downloadRefused(step string, cause error) error {
	return &authorityCheckStep{step: step, err: artifact.ErrDownloadUnavailable, cause: cause}
}
func downloadRefusedAs(step string, err error) error {
	return &authorityCheckStep{step: step, err: err}
}

// projectionRefused labels an approved-query authority refusal with its closed
// stage; it unwraps to err only and keeps cause (possibly nil) for its class.
func projectionRefused(step string, err, cause error) error {
	return &authorityCheckStep{step: step, err: err, cause: cause}
}
