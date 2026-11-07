package bootstrap

import (
	"context"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
)

var _ evidence.RecordingCanceller = (*ConnectorRecordings)(nil)

// CancelRecording restricts one finite manual recording attempt (packet
// metadata, raw packets, HTTP headers, syscall metadata or arguments). A
// queued node Stop is only a request; the original result and regional writer
// must finish before Collect can report cancellation. The node reports an
// early stop as a failure, so an unstored result is discarded; an active
// Store keeps stored-wins behavior.
func (h *ConnectorRecordings) CancelRecording(ctx context.Context, stop collector.RecordingStop) error {
	if ctx == nil || ctx.Err() != nil || !stop.Valid() {
		return value.ErrInvalid
	}
	until, ok := ctx.Deadline()
	if !ok {
		return value.ErrDenied
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.expireLocked(now)
	if !now.Before(until) || !now.Before(stop.WriteUntil.Add(recordingRetain)) {
		return value.ErrExpired
	}
	if held := h.logs[stop.CaptureID]; held != nil {
		return h.cancelLogsLocked(stop, held)
	}
	held := h.held[stop.CaptureID]
	if held == nil {
		if h.profiles[stop.CaptureID] != nil || h.heldCountLocked() >= maxHeldRecordings {
			return value.ErrUnavailable
		}
		// This fences a delayed start, but absence is never evidence of termination.
		held = &heldRecording{cancelOnly: true, recordingStop: &stop, cancelRequested: true, digest: stop.ExpectationDigest,
			expectation: artifact.ContextExpectation{CaptureUID: stop.CaptureID, Registration: artifact.Registration{Location: artifact.Location{AttemptID: stop.AttemptID}}},
			expires:     stop.WriteUntil.Add(recordingRetain), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
		h.held[stop.CaptureID] = held
		return nil
	}
	e := held.expectation
	if held.digest != stop.ExpectationDigest || e.Registration.Location.AttemptID != stop.AttemptID || held.recordingStop != nil && !held.recordingStop.Equal(stop) {
		return value.ErrDenied
	}
	if !held.cancelOnly && (e.Recording == nil || e.Snapshot != nil || held.snapshot != nil || e.Registration.Location.ClusterID != stop.ClusterID || !e.Registration.WriteUntil.Equal(stop.WriteUntil)) {
		return value.ErrDenied
	}
	if held.outcome.State == evidence.RecordingStored || held.outcome.State == evidence.RecordingCancelled {
		return nil
	}
	held.recordingStop, held.cancelRequested = &stop, true
	if held.stopStoreWait != nil {
		held.stopStoreWait()
	}
	if held.resultArrived || held.cancelOnly || held.cancelID != "" {
		return nil
	}
	if held.workID == "" {
		return value.ErrUnavailable
	}
	queue, ok := h.nodes.(interface {
		EnqueuePacketCancel(context.Context, string, string, string, time.Time) (collector.Work, error)
	})
	if !ok {
		return value.ErrUnavailable
	}
	if limit := now.Add(5 * time.Second); limit.Before(until) {
		until = limit
	}
	work, err := queue.EnqueuePacketCancel(ctx, held.nodeUID, stop.CaptureID, held.workID, until)
	if err != nil {
		return err
	}
	held.cancelID = work.ID
	return nil
}

// Called under the holder lock. Engine return is authenticated by the original
// node result; unlike snapshot Stop receipts, packet Stop receipts do not join.
func (h *ConnectorRecordings) recordingCancellation(held *heldRecording) (artifact.RecordingCancellation, bool) {
	stop := held.recordingStop
	if stop == nil || held.cancelOnly || held.snapshot != nil || !held.resultJoined || held.storing || held.outcome.State == evidence.RecordingStored {
		return artifact.RecordingCancellation{}, false
	}
	if proof := held.outcome.RecordingCancellation; proof != nil {
		return *proof, proof.Valid()
	}
	proof := artifact.RecordingCancellation{CaptureID: stop.CaptureID, AttemptID: stop.AttemptID, WriterPodUID: stop.WriterPodUID, WriterEpoch: stop.WriterEpoch, ExpectationDigest: stop.ExpectationDigest, JoinedAt: h.now().UTC().Truncate(time.Microsecond)}
	return proof, proof.Valid()
}
