package capture

// ErrStorageBindingExpired identifies only a structurally valid, matching
// binding whose original observation expired. It is availability, not a changed
// reviewed selection; a new protected observation must independently replace it.
var ErrStorageBindingExpired error = storageBindingExpired{}

type storageBindingExpired struct{}

func (storageBindingExpired) Error() string { return "context storage binding expired" }
func (storageBindingExpired) Unwrap() error { return ErrUnavailable }
