package audit

// These stages are selected only by the cleanup application, never by provider
// errors. Refusals retain the existing unavailable contract without exposing
// dependency text or converting an unknown effect into a successful one.
type operationCleanupFailure struct {
	step  string
	cause error
}

func (e *operationCleanupFailure) Error() string { return "operation cleanup: " + e.step }
func (e *operationCleanupFailure) Unwrap() error { return e.cause }

// OperationCleanupFailureStep accepts only this package's concrete refusal.
// Arbitrary dependency FixedStep/Error methods are deliberately not inspected.
func OperationCleanupFailureStep(err error) string {
	if e, ok := err.(*operationCleanupFailure); ok {
		return e.step
	}
	return ""
}
