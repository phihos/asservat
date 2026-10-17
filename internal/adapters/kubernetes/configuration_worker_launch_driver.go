package kubernetes

import cfg "asservat.local/asservat/internal/domain/configuration"

// This is only finite local control for CompleteLaunch, never an authority or
// a durable receipt-attempt fence. It owns no callback, timer, retry delay or
// replacement credential. Each admitted step still invokes the concrete full
// Advance path with its own original bounds and the original parent end.
type configurationWorkerLaunchRun struct {
	calls            int
	receiptUncertain bool
	last             ConfigurationWorkerLaunchAdvance
}

// Retain an earlier known original outcome if the next observation fails before
// it can read the journal. This value is historical progress only: an error
// always returns Spent, never a stale Pending/Acknowledged authority result.
func (r *configurationWorkerLaunchRun) observed(result ConfigurationWorkerLaunchAdvance, err error) ConfigurationWorkerLaunchAdvance {
	if result.Progress == 0 && r.last.Progress != 0 {
		result = r.last
		// Preserve historical uncertainty, not a permission to repeat a read
		// whose own bounded inspection has now failed before journal readback.
		result.needsInspection = false
	}
	result.receiptUncertain = result.receiptUncertain || r.receiptUncertain
	if err != nil && result.Progress != 0 {
		result.Progress = ConfigurationWorkerLaunchSpent
	}
	r.last = result
	return result
}

func (r *configurationWorkerLaunchRun) interrupted() ConfigurationWorkerLaunchAdvance {
	return r.observed(ConfigurationWorkerLaunchAdvance{}, cfg.ErrUnavailable)
}

func (r *configurationWorkerLaunchRun) continueAfter(result ConfigurationWorkerLaunchAdvance, err error, parentCurrent bool) bool {
	wasUncertain := r.receiptUncertain
	r.calls++
	if result.receiptUncertain {
		r.receiptUncertain = true
	}
	if r.calls >= 3 || !parentCurrent {
		return false
	}
	if err == nil {
		return result.Progress == ConfigurationWorkerLaunchPending && !wasUncertain
	}
	// A first uncertain receipt write gets at most one exact inspection in
	// this run. Even if the journal still says pending, that inspection cannot
	// write another receipt, repeat launch PUT or report an acknowledged result.
	return result.Progress == ConfigurationWorkerLaunchSpent && (result.needsInspection || result.receiptUncertain) && !wasUncertain
}
