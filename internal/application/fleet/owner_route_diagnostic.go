package fleet

import (
	"context"
	"errors"
	"time"
)

// Route stages are fixed at the call sites. Only standard cancellation classes
// cross this boundary; dependency text and diagnostic interfaces are not read.
// Without a reporter, the dependency error is not inspected.
func ownerRouteReadRefusal(ctx context.Context, stage string, err error) {
	if ctx == nil {
		return
	}
	report, ok := ctx.Value(refusalStepKey{}).(func(string))
	if !ok || report == nil {
		return
	}
	// Only a concrete closed local diagnostic may add endpoint substeps.
	var endpoint *ownerEndpointReadFailure
	if stage == "route-read/endpoints/read" && errors.As(err, &endpoint) {
		report(stage + "/" + endpoint.FixedStep() + RemainingBucket(ctx, time.Now()))
		return
	}
	reason := "other"
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		reason = "deadline"
	case errors.Is(err, context.Canceled):
		reason = "canceled"
	}
	report(stage + "/" + reason + RemainingBucket(ctx, time.Now()))
}
