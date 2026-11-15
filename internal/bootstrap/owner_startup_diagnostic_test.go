package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/mounts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

type startupPrivateError struct{}

func (startupPrivateError) Error() string { panic("private cause must never be rendered") }
func TestOwnerStartupDiagnosticClosedRenderingRetainsCause(t *testing.T) {
	private := startupPrivateError{}
	for _, v := range []struct {
		cause  error
		reason string
	}{{errors.Join(private, cfg.ErrDenied), "denied"}, {errors.Join(private, context.DeadlineExceeded), "deadline"}, {errors.Join(private, context.Canceled), "cancelled"}, {errors.Join(private, cfg.ErrChanged), "changed"}, {private, "unavailable"}} {
		cause := errors.Join(mounts.ErrUnavailable, v.cause)
		err := ownerStartupError(startupObservationRuntime, "none", ownerStartupError(startupSqlRoleProof, "enrollment", cause))
		line := OwnerStartupDiagnostic(err)
		if !strings.Contains(line, "phase=sql-role-proof role=enrollment reason="+v.reason+" ") || !errors.Is(err, private) || !errors.Is(err, mounts.ErrUnavailable) {
			t.Fatal("lost closed phase, role, reason or original errors.Is")
		}
		if got, ok := OwnerStartupDiagnosticLine(line); !ok || got != line {
			t.Fatal("own fixed record rejected")
		}
	}
	unknown := OwnerStartupDiagnostic(ownerStartupError(ownerStartupPhase(255), "synthetic-private-user", startupPrivateError{}))
	if !strings.Contains(unknown, "phase=unspecified role=none") {
		t.Fatal("caller-controlled detail rendered")
	}
}
func TestOwnerStartupDiagnosticRetainsCompositionStep(t *testing.T) {
	err := ownerStartupError(startupPublicContext, "none", &fixedStepError{"public-context", &fixedStepError{"fleet-settings", mounts.ErrUnavailable}})
	line := OwnerStartupDiagnostic(err)
	if !strings.Contains(line, "phase=public-context role=none reason=unavailable ") || !strings.HasSuffix(line, " step=public-context/fleet-settings") || !errors.Is(err, mounts.ErrUnavailable) {
		t.Fatal("lost closed public-context stage", line)
	}
	if got, ok := OwnerStartupDiagnosticLine(line); !ok || got != line {
		t.Fatal("composition stage record rejected")
	}
}
func TestOwnerStartupDiagnosticRejectsRawProcessOutput(t *testing.T) {
	good := OwnerStartupDiagnostic(ownerStartupError(startupSqlCredential, "registry", mounts.ErrUnavailable))
	for _, bad := range []string{"postgres://synthetic-private", "prefix " + good, good + "\npassword=synthetic", good + " extra", strings.Replace(good, "role=registry", "role=synthetic-private", 1), strings.Replace(good, "native=unspecified", "native=token-value", 1), strings.Replace(good, "reason=unavailable", "reason=synthetic-secret", 1), strings.Repeat("x", 513)} {
		if got, ok := OwnerStartupDiagnosticLine(bad); ok || got != "" {
			t.Fatal("untrusted process output accepted")
		}
	}
}
