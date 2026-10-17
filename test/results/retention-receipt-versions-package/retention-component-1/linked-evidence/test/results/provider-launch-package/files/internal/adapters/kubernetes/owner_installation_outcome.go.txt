package kubernetes

// These public stop reasons describe this invocation's observed disposition.
// They grant no refund, reset, retry or authority to create another object.
type OwnerInstallationStop string

const (
	OwnerInstallationUnverified OwnerInstallationStop = "original-result-unverified"
	OwnerInstallationSpent      OwnerInstallationStop = "spent-before-effect"
	OwnerInstallationExpired    OwnerInstallationStop = "original-root-expired"
	OwnerInstallationCancelled  OwnerInstallationStop = "cancelled"
	OwnerInstallationClosed     OwnerInstallationStop = "closed-or-already-run"
)

// The original cause is deliberately not copied into public progress text:
// provider/SQL diagnostics may contain confidential connection/material facts.
type ownerInstallationPhaseError struct {
	stop        OwnerInstallationStop
	operationID string
	cause       error
}

func (e *ownerInstallationPhaseError) Error() string {
	return "owner installation phase did not complete: " + string(e.stop)
}
func (e *ownerInstallationPhaseError) Unwrap() error { return e.cause }
