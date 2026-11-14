package kubernetes

// These private diagnostics contain only fixed check names. Causes retain the
// existing errors.Is contract but their text is never rendered. No driver error,
// protected identity/value or native response can become diagnostic output.
type ownerOperationCheck uint8

type ownerOperationDiagnostic struct {
	check  ownerOperationCheck
	cause  error
	detail *ownerOperationDiagnostic
	source *configurationWorkerDiagnostic
}
