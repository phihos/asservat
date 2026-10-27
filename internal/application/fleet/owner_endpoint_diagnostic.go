package fleet

import "context"

// Only this concrete closed diagnostic is trusted at the endpoint boundary.
// Arbitrary dependency FixedStep/Error methods remain unread.
type ownerEndpointReadFailure struct {
	step, reason string
	err          error
}

func (e *ownerEndpointReadFailure) Error() string     { return "owner endpoint observation failed" }
func (e *ownerEndpointReadFailure) Unwrap() error     { return e.err }
func (e *ownerEndpointReadFailure) FixedStep() string { return e.step + "/" + e.reason }

// OwnerEndpointFailure adds a closed diagnostic to the adapter's existing
// sanitized error class. It neither inspects provider text nor changes authority.
func OwnerEndpointFailure(ctx context.Context, step string, cause error) error {
	if cause == nil {
		return nil
	}
	if local, ok := cause.(*ownerEndpointReadFailure); ok {
		return local // A helper already identified the more precise local step.
	}
	switch step {
	case "namespace", "service-first-read", "service-first-identity", "service-first-selector", "account-read", "account-identity", "deployment-read", "deployment-identity", "slices-read", "slices-list", "slice-identity", "slice-endpoint", "slice-addresses", "slices-empty", "slices-pagination", "pod-read", "pod-identity", "pod-readiness", "pod-addresses", "replicaset-owner", "replicaset-read", "replicaset-identity", "deployment-owner", "service-final-read", "service-final-identity", "service-final-selector", "service-final-rv", "pod-final-read", "pod-final-rv", "pod-final-identity", "observation-current", "result":
	default:
		step = "unknown"
	}
	reason := "other"
	if ctx != nil {
		switch ctx.Err() {
		case context.Canceled:
			reason = "canceled"
		case context.DeadlineExceeded:
			reason = "deadline"
		}
	}
	return &ownerEndpointReadFailure{step: step, reason: reason, err: cause}
}
