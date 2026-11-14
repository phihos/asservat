package kubernetes

import (
	"errors"
	"testing"
)

type configurationSourceHostileError struct{}

func (configurationSourceHostileError) Error() string { panic("raw error text must never be rendered") }

func requireConfigurationSourceCode(t *testing.T, err error, want configurationSourceCheck, classification error) {
	t.Helper()
	var actual *configurationWorkerDiagnostic
	if err == nil || !errors.Is(err, classification) || !errors.As(err, &actual) || actual == nil || actual.check != want {
		t.Fatal("incorrect fixed source diagnostic", err, want, classification)
	}
}
