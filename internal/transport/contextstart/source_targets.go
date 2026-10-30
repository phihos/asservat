package contextstart

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

func (t Targets) ResolveOngoingRecorder(ctx context.Context, r targets.OngoingRecorderRequest) (targets.OngoingRecorderResolution, error) {
	values, err := t.ResolveOngoingRecorders(ctx, []targets.OngoingRecorderRequest{r})
	if err != nil {
		return targets.OngoingRecorderResolution{}, err
	}
	if !values[0].Recorder.ValidSource(t.Now()) {
		return targets.OngoingRecorderResolution{}, targets.ErrUnavailable
	}
	return values[0], nil
}

// ResolveOngoingRecorders shares exactly one original regional peer/source proof
// and round trip. Results retain cardinality/order; one unavailable target is a
// closed per-item refusal, never a truncated batch or a replacement target.
func (t Targets) ResolveOngoingRecorders(ctx context.Context, requests []targets.OngoingRecorderRequest) ([]targets.OngoingRecorderResolution, error) {
	if ctx == nil || ctx.Err() != nil || t.Router == nil || t.Now == nil || !targets.ValidOngoingRecorderBatch(requests) {
		return nil, targets.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var out []targets.OngoingRecorderResolution
	until, err := t.Router.Query(call, requests[0].Target.ClusterID, queryResolveOngoingRecorders, requests, &out)
	if err != nil {
		return nil, err
	}
	if call.Err() != nil || len(out) != len(requests) {
		return nil, targets.ErrUnavailable
	}
	now := t.Now()
	for i := range out {
		value, valid := validateOngoingRecorder(out[i], requests[i], until, now)
		if valid {
			out[i] = value
		} else {
			out[i] = targets.OngoingRecorderResolution{Recorder: targets.RecorderResolution{Recorder: targets.RecorderAnswer{Outcome: targets.RecorderUnavailable}}}
		}
	}
	return out, nil
}

func validateOngoingRecorder(out targets.OngoingRecorderResolution, r targets.OngoingRecorderRequest, until, now time.Time) (targets.OngoingRecorderResolution, bool) {
	if out.Recorder.Recorder.Source != nil {
		out.Recorder.Recorder.Source.FreshUntil = identity.Earlier(out.Recorder.Recorder.Source.FreshUntil, until)
	}
	c := out.Ceilings
	ceilings := collector.Ceilings{SourceLimits: collector.SourceLimits{MaxActiveSources: c.MaxActiveSources, InputBytesPerSecond: c.InputBytesPerSecond, InputBurstBytes: c.InputBurstBytes}, RingBytes: c.RingBytes, FrozenBytes: c.FrozenBytes}
	if !out.Recorder.ValidSource(now) || out.Recorder.Target.Request != r.Target || !ceilings.Valid() || !ceilings.SourceLimits.Enabled() {
		return targets.OngoingRecorderResolution{}, false
	}
	if !identity.Fresh(out.ReportedAt, out.ReportFreshUntil, now, collector.StatusStaleAfter) {
		return targets.OngoingRecorderResolution{}, false
	}
	if state := out.State; state != nil {
		status := collector.SourceStatus{SourceStoppedAt: state.SourceStoppedAt, SnapshotUntil: state.SnapshotUntil, SourceID: state.SourceID, Fence: state.Fence, IssuedAt: state.IssuedAt, LeafUntil: state.LeafUntil, Credit: state.Credit, ObservedBytes: state.ObservedBytes, Closed: state.Closed, Stopped: state.Stopped, InputUnknown: state.InputUnknown}
		if state.SourceID != r.SourceID || state.Fence != r.Fence || !status.Valid(state.ObservedAt) || !identity.Fresh(state.ObservedAt, state.FreshUntil, now, collector.StatusStaleAfter) {
			return targets.OngoingRecorderResolution{}, false
		}
	}
	return out, true
}
