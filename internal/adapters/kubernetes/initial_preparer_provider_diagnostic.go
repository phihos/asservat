package kubernetes

import (
	"errors"
	"fmt"
	"time"
)

// Durations are local diagnostic observations, never renewed authority. Only
// static phase names and clamped integer milliseconds may cross this boundary.
type initialPreparationProviderFailure struct {
	phase                                       string
	cause                                       error
	started, finished, parentUntil, activeUntil time.Time
}

func (e initialPreparationProviderFailure) Error() string {
	return "initial provider preparation " + InitialPreparationProviderDiagnostic(e) + ": unavailable"
}
func (e initialPreparationProviderFailure) Unwrap() error { return e.cause }
func initialProviderDiagnosticMS(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	if d >= time.Minute {
		return 60000
	}
	return d.Milliseconds()
}
func InitialPreparationProviderDiagnostic(err error) string {
	var e initialPreparationProviderFailure
	if !errors.As(err, &e) {
		return ""
	}
	switch e.phase {
	case "inputs", "request-owner", "binding", "material", "original-private-scope", "private-state", "provider-preflight", "parent-persist", "original-parent", "issue-claim", "before-issue", "provider-issue", "original-response-unresolved", "response-verify", "response-persist", "retained-response-verify", "final-workload", "final-protection":
	default:
		return ""
	}
	// No date, source identifier, cause string or provider response is rendered.
	parentStart, parentEnd, activeEnd := int64(-1), int64(-1), int64(-1)
	if !e.parentUntil.IsZero() {
		parentStart = initialProviderDiagnosticMS(e.parentUntil.Sub(e.started))
		parentEnd = initialProviderDiagnosticMS(e.parentUntil.Sub(e.finished))
	}
	if !e.activeUntil.IsZero() {
		activeEnd = initialProviderDiagnosticMS(e.activeUntil.Sub(e.finished))
	}
	return fmt.Sprintf("phase=%s elapsed_ms=%d parent_start_ms=%d parent_remaining_ms=%d original_operation_remaining_ms=%d", e.phase, initialProviderDiagnosticMS(e.finished.Sub(e.started)), parentStart, parentEnd, activeEnd)
}
