package capture

import "context"

// Keep provider errors, identities, parameters and object/key locators out of
// diagnostics. The caller selects each stage from fixed words at its boundary.
func (s HistoryParameterService) reportFailure(ctx context.Context, operation, stage string, failure error) {
	if failure == nil || s.ReportFailure == nil {
		return
	}
	state := "live"
	if ctx != nil {
		until, bounded := ctx.Deadline()
		switch {
		case ctx.Err() == context.DeadlineExceeded || bounded && s.Now != nil && !s.Now().Before(until):
			state = "deadline"
		case ctx.Err() != nil:
			state = "canceled"
		}
	}
	s.ReportFailure(operation + "/" + stage + "/" + state)
}
