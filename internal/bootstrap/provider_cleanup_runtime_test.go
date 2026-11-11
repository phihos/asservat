package bootstrap

import (
	"bytes"
	"errors"
	"testing"

	"asservat.local/asservat/internal/adapters/kms"
	auditapp "asservat.local/asservat/internal/application/audit"
)

// Exercise the actual pending-return branch rather than fabricating a worker
// success. Refused refresh stays pending and retains the provider error class.
func TestProviderCleanupRefusedRefreshReportsStageWithoutStoppingActor(t *testing.T) {
	d := &CaptureCleanupWorkerDeployment{providers: &kms.InstalledConfigurationProviderEffects{}}
	err, current := d.advanceProviderCleanup(t.Context(), "never-selected-row")
	if !current || !errors.Is(err, kms.ErrKeyService) || cleanupRuntimeEvent(err) != "provider-refresh/unavailable" {
		t.Fatalf("pending refresh stage/class/current changed: %s/%t", cleanupRuntimeEvent(err), current)
	}
}

type privateCleanupError struct{}

func (privateCleanupError) Error() string     { panic("provider text must not enter diagnostics") }
func (privateCleanupError) FixedStep() string { panic("provider diagnostic must not enter event keys") }
func TestProviderCleanupDiagnosticsKeepOnlyLocalStageAndClass(t *testing.T) {
	private := privateCleanupError{}
	err := &cleanupRuntimeError{"healthy", private}
	var out bytes.Buffer
	report := eventLog(&out, "operation cleanup")
	for range 5 {
		report(cleanupRuntimeEvent(err))
	}
	if !errors.Is(err, private) || out.String() != "operation cleanup: healthy/unavailable (1)\noperation cleanup: healthy/unavailable (2)\noperation cleanup: healthy/unavailable (4)\n" {
		t.Fatal("private diagnostics or repeated pending failure escaped bounded log")
	}
}

func TestProviderCleanupReportsOnlyApplicationOwnedInnerStage(t *testing.T) {
	err := (auditapp.OperationCleanup{}).Advance(t.Context(), "never-selected-row")
	if !errors.Is(err, auditapp.ErrUnavailable) || cleanupRuntimeEvent(&cleanupRuntimeError{"healthy", err}) != "healthy/input/unavailable" {
		t.Fatal("application refusal stage lost")
	}
	if auditapp.OperationCleanupFailureStep(privateCleanupError{}) != "" {
		t.Fatal("foreign stage accepted")
	}
}
