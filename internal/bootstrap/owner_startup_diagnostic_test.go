package bootstrap

import (
	"asservat.local/asservat/internal/adapters/mounts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
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
func TestOwnerStartupDiagnosticRejectsRawProcessOutput(t *testing.T) {
	good := OwnerStartupDiagnostic(ownerStartupError(startupSqlCredential, "registry", mounts.ErrUnavailable))
	for _, bad := range []string{"postgres://synthetic-private", "prefix " + good, good + "\npassword=synthetic", good + " extra", strings.Replace(good, "role=registry", "role=synthetic-private", 1), strings.Replace(good, "native=unspecified", "native=token-value", 1), strings.Replace(good, "reason=unavailable", "reason=synthetic-secret", 1), strings.Repeat("x", 513)} {
		if got, ok := OwnerStartupDiagnosticLine(bad); ok || got != "" {
			t.Fatal("untrusted process output accepted")
		}
	}
}
func TestOwnerObservationLoaderReportsInputPhaseBeforeProviderEffects(t *testing.T) {
	in, dir, _ := ownerInputFixture(t)
	// Actual fixed-file decoder failure, before native clients or SQL credentials.
	writeOwnerJSON(t, dir, "deployment.json", map[string]string{"unexpected": "synthetic-private"})
	d, err := NewOwnerObservationDeployment(context.Background(), in.files, runtimeID)
	if d != nil {
		d.Close()
		t.Fatal("invalid projection started runtime")
	}
	if !errors.Is(err, mounts.ErrUnavailable) || !strings.Contains(OwnerStartupDiagnostic(err), "phase=inputs ") {
		t.Fatal("input failure phase missing", err)
	}
}
func TestOwnerObservationRuntimeReportsOriginalSetupDeadline(t *testing.T) {
	f, c := observationRuntimeConfig(t)
	s := &observationSetupReader{base: f}
	c.Configuration = s
	until := time.Now().Add(40 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), until)
	defer cancel()
	d, err := newOwnerObservationRuntime(context.Background(), ctx, c)
	if d != nil {
		d.Close()
		t.Fatal("late source accepted")
	}
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, value.ErrUnavailable) || !s.deadline.Equal(until) || f.signings.Load() != 0 || f.routes.Load() != 0 || !strings.Contains(OwnerStartupDiagnostic(err), "phase=runtime-configuration role=none reason=deadline ") {
		t.Fatal("original setup failure misclassified or performed effects", err)
	}
}
