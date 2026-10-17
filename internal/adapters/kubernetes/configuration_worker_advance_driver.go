package kubernetes

import cfg "asservat.local/asservat/internal/domain/configuration"

// This is only finite local control for CompleteInputs, never an authority or
// a durable receipt-attempt fence. It owns no callback, timer, retry delay or
// replacement credential. Each admitted step still invokes the concrete full
// Advance path with its own original bounds and the original parent end.
type configurationWorkerInputRun struct {
	calls            int
	receiptUncertain bool
	last             ConfigurationWorkerInputAdvance
}

// Retain an earlier known original outcome if the next observation fails before
// it can read the journal. This value is historical progress only: an error
// always returns Spent, never a stale Pending/Acknowledged authority result.
func (r *configurationWorkerInputRun) observed(result ConfigurationWorkerInputAdvance, err error) ConfigurationWorkerInputAdvance {
	if result.Progress == 0 && r.last.Progress != 0 {
		result = r.last
		// Preserve historical uncertainty, not a permission to repeat a read
		// whose own bounded inspection has now failed before journal readback.
		result.needsInspection = false
	}
	result.receiptUncertain = result.receiptUncertain || r.receiptUncertain
	if err != nil && result.Progress != 0 {
		result.Progress = ConfigurationWorkerInputSpent
	}
	r.last = result
	return result
}

func (r *configurationWorkerInputRun) interrupted() ConfigurationWorkerInputAdvance {
	return r.observed(ConfigurationWorkerInputAdvance{}, cfg.ErrUnavailable)
}

func (r *configurationWorkerInputRun) continueAfter(result ConfigurationWorkerInputAdvance, err error, parentCurrent bool) bool {
	wasUncertain := r.receiptUncertain
	r.calls++
	if result.receiptUncertain {
		r.receiptUncertain = true
	}
	if r.calls >= 3 || !parentCurrent {
		return false
	}
	if err == nil {
		return result.Progress == ConfigurationWorkerInputPending && !wasUncertain
	}
	// A first uncertain receipt write gets at most one exact inspection in
	// this run. Even if the journal still says pending, that inspection cannot
	// write another receipt, repeat CREATE or report an acknowledged result.
	return result.Progress == ConfigurationWorkerInputSpent && (result.needsInspection || result.receiptUncertain) && !wasUncertain
}
