package capture

import (
	"context"
	"errors"
	"time"
)

// contextPreviewFailure keeps a private, fixed stage without including target,
// identity, provider or SQL error text. Unwrap preserves public classification.
// Only this package can construct it; dependency-supplied FixedStep methods are
// deliberately not copied into the diagnostic.
type contextPreviewFailure struct {
	stage string
	cause error
}

func (e *contextPreviewFailure) Error() string     { return "context preview unavailable" }
func (e *contextPreviewFailure) Unwrap() error     { return e.cause }
func (e *contextPreviewFailure) FixedStep() string { return e.stage }

func previewFailure(stage string, cause error) error {
	var previous *contextPreviewFailure
	if errors.As(cause, &previous) {
		return cause
	}
	return &contextPreviewFailure{stage: stage, cause: cause}
}

func (s ContextInvestigation) reportPreviewFailure(err error) {
	var failure *contextPreviewFailure
	if s.ReportPreviewFailure != nil && errors.As(err, &failure) {
		s.ReportPreviewFailure(failure.stage)
	}
}

func previewEligibilityFailure(reason string) string {
	switch reason {
	case "AuthorityUnavailable":
		return "facts/eligibility/authority"
	case "IdentityUnavailable":
		return "facts/eligibility/identity"
	case "PermissionUnavailable":
		return "facts/eligibility/permission"
	case "ExplicitDeny":
		return "facts/eligibility/deny"
	case "InsufficientScope":
		return "facts/eligibility/scope"
	case "NoEntitlement":
		return "facts/eligibility/entitlement"
	default:
		return "facts/eligibility"
	}
}

// coldStorageRetryRoom is the request-window time a second preview attempt
// needs: a warm installed preview measured 0.6 s, plus the 750 ms response
// reserve. A scheduling choice, not an authority interval (ADR-314).
const coldStorageRetryRoom = 2 * time.Second

// retryColdStorage runs one more complete preview attempt when the first
// ended at the readiness tail: its binding had expired and the refresh it
// demanded had not landed yet (ADR-314). The second attempt reads identity,
// recovery, target and every other fact again under its own bounds; nothing
// from the first attempt is reused and the caller's deadline is unchanged.
func retryColdStorage[T any](ctx context.Context, attempt func() (T, error)) (T, error) {
	r, err := attempt()
	var failure *contextPreviewFailure
	if !errors.As(err, &failure) || failure.stage != storageReadinessTailStage || ctx.Err() != nil {
		return r, err
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < coldStorageRetryRoom {
		return r, err
	}
	return attempt()
}
