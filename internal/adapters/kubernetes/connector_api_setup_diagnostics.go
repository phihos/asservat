package kubernetes

import (
	"errors"
	"strings"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Keep Begin's original unavailable classification; copy only this private
// producer's fixed code, original cutoff and completed-check marks (fixed names
// and durations). Its dependency error does not escape through the opening
// diagnostic, and the receiving side restricts the marks again.
func connectorAPISetupDiagnostic(err error) error {
	var step *connectorAPIStepError
	if errors.As(err, &step) && step.phase != "" {
		marks := ""
		if _, rest, ok := strings.Cut(step.step, " after ["); ok {
			marks, _, _ = strings.Cut(rest, "]")
		}
		return &connectorAPIStepError{phase: step.phase, until: step.until, step: "setup after [" + marks + "]", err: cfg.ErrUnavailable}
	}
	return cfg.ErrUnavailable
}
