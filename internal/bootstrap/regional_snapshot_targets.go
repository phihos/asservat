package bootstrap

import (
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"fmt"
	"time"
)

// ResolveSourceSnapshot reads only the exact authenticated node/source report.
// Original is retained provenance supplied from protected source acceptance;
// no Pod read or newly stamped PodResolution can resurrect a deleted target.
func (t reportedTargets) ResolveSourceSnapshot(ctx context.Context, original targets.SourceSnapshotTarget) (targets.SourceSnapshotResolution, error) {
	var out targets.SourceSnapshotResolution
	if ctx == nil || ctx.Err() != nil || !original.Valid() || t.recordings == nil {
		return out, targets.ErrInvalid
	}
	registry, ok := t.recordings.nodes.(interface {
		NodeByUID(string) (delivery.NodeView, bool)
	})
	if !ok {
		return out, targets.ErrUnavailable
	}
	now := t.recordings.now()
	until := now.Add(5 * time.Second)
	if end, ok := ctx.Deadline(); !ok {
		return out, targets.ErrInvalid
	} else {
		until = identity.Earlier(until, end)
	}
	view, ok := registry.NodeByUID(original.NodeUID)
	if !ok || !view.Current || view.Report == nil || view.Identity.NodeUID != original.NodeUID || view.Identity.BootID != original.BootID || view.Identity.PodUID != original.CollectorPodUID || view.Identity.Epoch != original.CollectorEpoch {
		t.refused("node")
		return out, targets.ErrUnavailable
	}
	report := view.Report
	reportUntil := report.ObservedAt.Add(collector.StatusStaleAfter)
	until = identity.Earlier(until, reportUntil)
	for _, state := range report.Sources {
		if state.SourceID != original.SourceID || state.Fence != original.Fence {
			continue
		}
		out = targets.SourceSnapshotResolution{Original: original, Process: targets.PacketSourceObservation{PodUID: original.Request.PodUID, NodeUID: original.NodeUID, BootID: original.BootID, CollectorPodUID: original.CollectorPodUID, CollectorEpoch: original.CollectorEpoch, ObservedAt: now, FreshUntil: until}, State: targets.RecorderSourceState{SourceID: state.SourceID, Fence: state.Fence, IssuedAt: state.IssuedAt, LeafUntil: state.LeafUntil, Credit: state.Credit, ObservedBytes: state.ObservedBytes, Closed: state.Closed, Stopped: state.Stopped, InputUnknown: state.InputUnknown, SourceStoppedAt: state.SourceStoppedAt, SnapshotUntil: state.SnapshotUntil, ObservedAt: report.ObservedAt, FreshUntil: reportUntil}, ReportedAt: report.ObservedAt, ReportFreshUntil: reportUntil, ObservedAt: now, FreshUntil: until}
		if ctx.Err() != nil || !out.Valid(t.recordings.now()) {
			t.refused("invalid")
			return targets.SourceSnapshotResolution{}, targets.ErrUnavailable
		}
		return out, nil
	}
	t.refused(fmt.Sprintf("missing sources=%d", len(report.Sources)))
	return out, targets.ErrUnavailable
}

// refused logs a fixed source snapshot refusal reason; no identifiers.
func (t reportedTargets) refused(reason string) {
	if t.report != nil {
		t.report("source-snapshot", reason)
	}
}
