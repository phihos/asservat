package capture

import "errors"

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
