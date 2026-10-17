package bootstrap

import (
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestInitialPreparerLoadDiagnosticHidesCauseAndPreservesIdentity(t *testing.T) {
	secret := errors.New("DO-NOT-LEAK-provider-token-sql-password")
	err := initialPreparerLoadFailure{phase: "sql-connection-inputs", cause: secret}
	if !errors.Is(err, secret) || strings.Contains(err.Error(), secret.Error()) || err.Error() != "initial preparation loader sql-connection-inputs: unavailable" {
		t.Fatal("unsafe loader diagnostic")
	}
	_, e := NewInitialPreparationDeployment(context.Background(), nil)
	if !errors.Is(e, mounts.ErrUnavailable) || e.Error() != "initial preparation loader process-inputs: unavailable" {
		t.Fatal("constructor phase or cause missing", e)
	}
}

func TestInitialPreparerRunDiagnosticHidesCauseAndPreservesIdentity(t *testing.T) {
	secret := errors.New("DO-NOT-LEAK-provider-token-sql-password")
	for _, phase := range []string{"declare", "gated-pod", "final-inputs", "probe", "request-drain", "final-cancellation"} {
		err := initialPreparerRunFailure{phase: phase, cause: secret}
		if !errors.Is(err, secret) || strings.Contains(err.Error(), secret.Error()) || err.Error() != "initial preparation run "+phase+": unavailable" {
			t.Fatal("unsafe run diagnostic")
		}
	}
	for _, phase := range []string{"sql-bind", "sql-state-persist", "sql-provision", "provider-wrap", "provider-unwrap", "provider-projection"} {
		err := initialPreparerRunFailure{phase: "sql-and-providers", cause: initialPreparerRunFailure{phase: phase, cause: secret}}
		if !errors.Is(err, secret) || strings.Contains(err.Error(), secret.Error()) || err.Error() != "initial preparation run sql-and-providers/"+phase+": unavailable" {
			t.Fatal("unsafe nested run diagnostic")
		}
	}
	var d *InitialPreparationDeployment
	if _, err := d.Run(); !errors.Is(err, mounts.ErrUnavailable) || err.Error() != "initial preparation run run-inputs: unavailable" {
		t.Fatal("run phase or cause missing", err)
	}
	if err := d.prepareSQL(context.Background()); !errors.Is(err, mounts.ErrUnavailable) || err.Error() != "initial preparation run sql-inputs: unavailable" {
		t.Fatal("SQL phase or cause missing", err)
	}
}

func TestInitialPreparerRunPreservesOnlyQualifiedProviderDiagnostic(t *testing.T) {
	var binder *kube.InitialPreparationCredentialBinder
	_, _, cause := binder.PrepareProvider(context.Background(), "wrap", nil)
	err := initialPreparerRunFailure{phase: "sql-and-providers", cause: initialPreparerRunFailure{phase: "provider-wrap", cause: cause}}
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "sql-and-providers/provider-wrap: unavailable (phase=inputs elapsed_ms=") || !strings.Contains(err.Error(), "parent_remaining_ms=-1 original_operation_remaining_ms=-1)") {
		t.Fatal("provider detail lost", err)
	}
}
