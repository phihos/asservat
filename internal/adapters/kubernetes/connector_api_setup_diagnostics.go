package kubernetes

import (
	"errors"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Keep Begin's original unavailable classification; copy only this private
// producer's fixed code and original cutoff. Its dependency error and elapsed
// trace do not escape through the opening diagnostic.
func connectorAPISetupDiagnostic(err error) error {
	var step *connectorAPIStepError
	if errors.As(err, &step) && step.phase != "" {
		return &connectorAPIStepError{phase: step.phase, until: step.until, step: "setup", err: cfg.ErrUnavailable}
	}
	return cfg.ErrUnavailable
}
