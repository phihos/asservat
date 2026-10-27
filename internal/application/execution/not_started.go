package execution

import (
	"context"
	"errors"

	"asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// TemporarilyUnavailable is for composing callers that may inspect errors; the
// runner itself never inspects a dependency error. It reports whether a refusal before any start effect
// is a temporary unavailability that an explicit continuation may retry
// (ADR-250). A definite refusal keeps its own class: denial or revocation,
// expiry (including the original deadline), a changed or replaced target, a
// conflict or an invalid request is never a retryable not-started start.
func TemporarilyUnavailable(err error) bool {
	if err == nil {
		return false
	}
	for _, definite := range []error{
		value.ErrDenied, value.ErrExpired, value.ErrConflict, value.ErrInvalid, value.ErrPreparationUncertain,
		identity.ErrDenied, identity.ErrInvalid,
		targets.ErrDenied, targets.ErrChanged, targets.ErrInvalid, targets.ErrUnsupported,
		capture.ErrDenied, capture.ErrChanged, capture.ErrInvalid, capture.ErrConflict, capture.ErrAcquisitionClosed,
		context.DeadlineExceeded,
	} {
		if errors.Is(err, definite) {
			return false
		}
	}
	return true
}
