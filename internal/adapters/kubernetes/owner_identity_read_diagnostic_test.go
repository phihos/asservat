package kubernetes

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
	"context"
	"errors"
	"testing"
)

type ownerReadPrivateError struct{}

func (ownerReadPrivateError) Error() string { panic("private cause must never be rendered") }
func TestOwnerIdentityReadDiagnosticOnlyRendersClosedChecks(t *testing.T) {
	cause := ownerReadPrivateError{}
	inner := error(errors.Join(cfg.ErrDenied, context.DeadlineExceeded, cause))
	check := ownerReadCredentialsRead
	ownerReadAnnotate(&check, &inner)
	check = ownerReadProjections
	ownerReadAnnotate(&check, &inner)
	if inner.Error() != "owner identity unavailable: check=projections detail=credentials-read" || !errors.Is(inner, cause) || !errors.Is(inner, cfg.ErrDenied) || !errors.Is(inner, context.DeadlineExceeded) {
		t.Fatal("diagnostic lost closed detail or original error identity")
	}
	check = OwnerIdentityReadCheck(255)
	e := error(cause)
	ownerReadAnnotate(&check, &e)
	if e.Error() != "owner identity unavailable: check=unspecified detail=unspecified" {
		t.Fatal("unknown check rendered caller input")
	}
}

func TestOwnerIdentityReadDiagnosticSeparatesReadAndChangedIdentity(t *testing.T) {
	for _, tc := range []struct {
		step  OwnerIdentityReadCheck
		cause error
		want  string
	}{{ownerReadLivePodRead, context.DeadlineExceeded, "initial-pod/live-pod-read/deadline"}, {ownerReadLivePodRead, cfg.ErrUnavailable, "initial-pod/live-pod-read"}} {
		e := tc.cause
		step := tc.step
		ownerReadAnnotate(&step, &e)
		step = ownerReadInitialPod
		ownerReadAnnotate(&step, &e)
		var diagnostic interface{ FixedStep() string }
		if !errors.As(e, &diagnostic) || diagnostic.FixedStep() != tc.want {
			t.Fatal("unsafe or indistinguishable failure", e)
		}
	}
}
