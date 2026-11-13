package bootstrap

import (
	"context"
	"errors"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// The download worker profile's fixed, unqualified limits (ADR-204): one
// process container per download. They are bounds, not a qualified capacity
// claim.
const (
	downloadWorkerCPUMillis   = 500
	downloadWorkerMemoryBytes = 384 << 20
)

// fixedStepError names a fixed sub-step for a stop message.
type fixedStepError struct {
	step string
	err  error
}

func (e *fixedStepError) Error() string { return e.step }
func (e *fixedStepError) Unwrap() error { return e.err }

// FixedStep appends a nested fixed step, so labels compose across layers.
func (e *fixedStepError) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}

func errorClass(err error) string {
	switch {
	case errors.Is(err, cfg.ErrChanged):
		return "changed"
	case errors.Is(err, cfg.ErrInvalid):
		return "invalid"
	case errors.Is(err, cfg.ErrDenied):
		return "denied"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	}
	return "unavailable"
}
