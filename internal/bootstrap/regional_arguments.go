package bootstrap

import (
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/targets"
)

var _ evidence.ArgumentContextRecorder = (*preparedRecording)(nil)

// StartArgumentRecording transfers the prepared writer only through the exact
// source queue. The original SQL argument permit supplies all observation
// credits and deadlines; this boundary neither issues nor renews them.
func (p *preparedRecording) StartArgumentRecording(ctx context.Context, pin artifact.PinnedPod, started, until time.Time, source targets.PacketSourceObservation, permit collector.ArgumentObservationPermit) (time.Time, error) {
	h, e := p.holder, p.expectation
	r, b := e.Recording, permit.Binding
	now := h.now()
	if ctx == nil || ctx.Err() != nil || !source.Valid(now) || !permit.ValidFinite(now) || !now.Before(until) || started.After(now) || started.Before(permit.StartedAt) ||
		pin.UID != e.PodUID || pin.NamespaceUID != e.NamespaceUID || source.PodUID != e.PodUID || !r.Valid() || r.Arguments == nil ||
		e.NativeType != artifact.SyscallArgumentsArtifact || e.DataClass != "raw" ||
		b.CaptureID != e.CaptureUID || b.ActionID != e.ActionID || b.PodUID != e.PodUID || b.NodeUID != source.NodeUID || b.BootID != source.BootID || b.CollectorPodUID != source.CollectorPodUID || b.CollectorEpoch != source.CollectorEpoch ||
		(e.NodeUID != "" && e.NodeUID != source.NodeUID) || (e.NodeBootID != "" && e.NodeBootID != source.BootID) ||
		b.ExpectationDigest != [32]byte(evidence.ContextExpectationDigest(e)) || permit.Duration != time.Duration(r.DurationMillis)*time.Millisecond || permit.SessionUntil.After(e.Registration.WriteUntil) {
		return time.Time{}, value.ErrDenied
	}
	a, s := r.Arguments, r.Syscalls
	if b.ProgramDigest != [32]byte(a.ProgramDigest) || b.DefinitionDigest != [32]byte(a.DefinitionDigest) || b.AccountingRule != [32]byte(a.AccountingRule) ||
		permit.MaxProbeBytes != a.MaxProbeBytes || permit.MaxBytesPerEvent != a.MaxBytesPerEvent || permit.BytesPerSecond != a.MaxBytesPerSecond || permit.CaptureBuffers != a.CaptureBuffers ||
		permit.EventsPerSecond != s.MaxEventsPerSecond || permit.MaxTrackedThreads != int64(s.MaxTrackedThreads) {
		return time.Time{}, value.ErrDenied
	}
	work := collector.PacketCapture{CaptureID: e.CaptureUID, PodUID: e.PodUID, Duration: permit.Duration, MaxBytes: r.MaxBytes, Arguments: &permit,
		Syscalls: &collector.SyscallFilter{Names: slices.Clone(s.Names), ErrorsOnly: s.ErrorsOnly, MaxEvents: s.MaxEvents, MaxTrackedThreads: s.MaxTrackedThreads}, MaxEventsPerSecond: s.MaxEventsPerSecond}
	if !work.Valid() {
		return time.Time{}, value.ErrDenied
	}
	queue, ok := h.nodes.(interface {
		EnqueuePacketExpected(context.Context, targets.PacketSourceObservation, collector.PacketCapture, time.Time) (collector.Work, error)
	})
	if !ok {
		return time.Time{}, value.ErrUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.prepared == nil {
		return time.Time{}, value.ErrDenied
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now = h.now()
	h.expireLocked(now)
	if ctx.Err() != nil || !source.Valid(now) || !permit.ValidFinite(now) || !now.Before(until) || h.heldCountLocked() >= maxHeldRecordings || h.held[e.CaptureUID] != nil || h.profiles[e.CaptureUID] != nil || h.logs[e.CaptureUID] != nil {
		return time.Time{}, value.ErrUnavailable
	}
	prepared := p.prepared
	p.prepared = nil // even an unknown enqueue reply consumes this writer
	queued := now.UTC().Truncate(time.Microsecond)
	held := &heldRecording{expectation: e, digest: evidence.ContextExpectationDigest(e), prepared: prepared, nodeUID: source.NodeUID, argumentSource: &source, queued: queued,
		expires: e.Registration.WriteUntil.Add(recordingRetain), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
	// Retain uncertainty even when the enqueue reply is lost. No new start or
	// cancellation proof may infer that absence of a work ID means no effect.
	h.held[e.CaptureUID] = held
	w, err := queue.EnqueuePacketExpected(ctx, source, work, permit.StartBy)
	if err != nil {
		held.prepared = nil
		return time.Time{}, value.ErrUnavailable
	}
	held.workID = w.ID
	return queued, nil
}
