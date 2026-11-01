package bootstrap

import (
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
	"context"
)

func (t reportedTargets) ResolveOngoingRecorder(ctx context.Context, r targets.OngoingRecorderRequest) (targets.OngoingRecorderResolution, error) {
	if !r.Valid() {
		return targets.OngoingRecorderResolution{}, targets.ErrInvalid
	}
	p, node, err := t.PodTargets.ResolvePacketPod(ctx, r.Target)
	if err != nil {
		return targets.OngoingRecorderResolution{}, err
	}
	out := targets.OngoingRecorderResolution{Recorder: t.packetTargetAvailability(ctx, p, node, true)}
	if t.recordings == nil || !out.Recorder.ValidSource(t.recordings.now()) {
		return targets.OngoingRecorderResolution{}, targets.ErrUnavailable
	}
	v, ok := t.recordings.nodes.NodeByName(node)
	s := out.Recorder.Recorder.Source
	if !ok || !v.PacketRecorderAvailable() || v.Report == nil || v.Identity.NodeUID != s.NodeUID || v.Identity.BootID != s.BootID || v.Identity.PodUID != s.CollectorPodUID || v.Identity.Epoch != s.CollectorEpoch {
		return targets.OngoingRecorderResolution{}, targets.ErrUnavailable
	}
	c := v.Report.Budget.Ceilings
	if !c.SourceLimits.Enabled() {
		return targets.OngoingRecorderResolution{}, targets.ErrUnavailable
	}
	out.ReportedAt = v.Report.ObservedAt
	out.ReportFreshUntil = v.Report.ObservedAt.Add(collector.StatusStaleAfter)
	out.Ceilings = targets.RecorderSourceCeilings{MaxActiveSources: c.MaxActiveSources, InputBytesPerSecond: c.InputBytesPerSecond, InputBurstBytes: c.InputBurstBytes, RingBytes: c.RingBytes, FrozenBytes: c.FrozenBytes}
	if r.SourceID != "" {
		for _, state := range v.Report.Sources {
			if state.SourceID == r.SourceID && state.Fence == r.Fence {
				out.State = &targets.RecorderSourceState{SourceStoppedAt: state.SourceStoppedAt, SnapshotUntil: state.SnapshotUntil, SourceID: state.SourceID, Fence: state.Fence, IssuedAt: state.IssuedAt, LeafUntil: state.LeafUntil, Credit: state.Credit, ObservedBytes: state.ObservedBytes, Closed: state.Closed, Stopped: state.Stopped, InputUnknown: state.InputUnknown, ObservedAt: v.Report.ObservedAt, FreshUntil: v.Report.ObservedAt.Add(collector.StatusStaleAfter)}
				break
			}
		}
	}
	// This second in-process registry lookup adds no API request or refreshed
	// proof. Preserve the first target/source observation and all cutoffs.
	if ctx == nil || ctx.Err() != nil || !out.Recorder.ValidSource(t.recordings.now()) {
		return targets.OngoingRecorderResolution{}, targets.ErrUnavailable
	}
	return out, nil
}

func (t reportedTargets) ResolveOngoingRecorders(ctx context.Context, requests []targets.OngoingRecorderRequest) ([]targets.OngoingRecorderResolution, error) {
	if ctx == nil || ctx.Err() != nil || !targets.ValidOngoingRecorderBatch(requests) {
		return nil, targets.ErrInvalid
	}
	out := make([]targets.OngoingRecorderResolution, len(requests))
	for i, r := range requests {
		value, err := t.ResolveOngoingRecorder(ctx, r)
		if err != nil {
			out[i] = targets.OngoingRecorderResolution{Recorder: targets.RecorderResolution{Recorder: targets.RecorderAnswer{Outcome: targets.RecorderUnavailable}}}
			continue
		}
		out[i] = value
	}
	// The existing resolver still performs its per-Pod Kubernetes reads. This
	// batch removes repeated regional proof/transport round trips, not API reads.
	return out, nil
}
