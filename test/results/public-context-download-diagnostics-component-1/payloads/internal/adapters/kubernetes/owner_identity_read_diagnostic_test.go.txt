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
