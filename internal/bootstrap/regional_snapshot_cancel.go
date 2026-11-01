package bootstrap

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"context"
	"time"
)

var _ evidence.SourceSnapshotCanceller = (*ConnectorRecordings)(nil)

func (h *ConnectorRecordings) CancelSourceSnapshot(ctx context.Context, x collector.SourceSnapshot) error {
	if ctx == nil || ctx.Err() != nil || !x.Valid() {
		return value.ErrDenied
	}
	queue, ok := h.nodes.(interface {
		EnqueueSourceSnapshotCancel(context.Context, collector.SourceSnapshot, time.Time) (collector.Work, error)
	})
	if !ok {
		return value.ErrUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expireLocked(h.now())
	held := h.held[x.CaptureID]
	if held != nil {
		if held.digest != artifact.Digest(x.ExpectationDigest) || held.expectation.Registration.Location.AttemptID != x.AttemptID || held.snapshot == nil || !held.snapshot.Equal(x) {
			return value.ErrConflict
		}
		if held.outcome.State == evidence.RecordingStored || held.outcome.State == evidence.RecordingCancelled {
			return nil
		}
	} else if len(h.held) >= maxHeldRecordings {
		return value.ErrUnavailable
	}
	until := h.now().Add(5 * time.Second)
	if end, ok := ctx.Deadline(); !ok {
		return value.ErrDenied
	} else if end.Before(until) {
		until = end
	}
	work, err := queue.EnqueueSourceSnapshotCancel(ctx, x, until)
	if err != nil {
		return err
	}
	if held == nil {
		e := artifact.ContextExpectation{CaptureUID: x.CaptureID, Registration: artifact.Registration{Location: artifact.Location{AttemptID: x.AttemptID}}}
		held = &heldRecording{cancelOnly: true, snapshot: &x, expectation: e, digest: artifact.Digest(x.ExpectationDigest), nodeUID: x.Binding.NodeUID, expires: x.Request.ProcessingUntil.Add(recordingRetain), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
		// Restrictive late cancellation can retain only bounded control metadata;
		// it does not extend processing/write authority of the old request.
		if !h.now().Before(held.expires) {
			held.expires = h.now().Add(recordingRetain)
		}
		h.held[x.CaptureID] = held
	}
	held.cancelID, held.cancelRequested = work.ID, true
	return nil
}

// Called under holder lock. The node's receipt means its copy/upload joined;
// the holder additionally waits for its own encryption/store call to return.
func (h *ConnectorRecordings) snapshotCancellation(held *heldRecording) (artifact.SourceSnapshotCancellation, bool) {
	if held.snapshot == nil || held.storing || held.cancelID == "" {
		return artifact.SourceSnapshotCancellation{}, false
	}
	reader, ok := h.nodes.(interface {
		SourceSnapshotCancellation(collector.SourceSnapshot, string) (time.Time, bool)
	})
	if !ok {
		return artifact.SourceSnapshotCancellation{}, false
	}
	joined, ok := reader.SourceSnapshotCancellation(*held.snapshot, held.cancelID)
	if !ok {
		return artifact.SourceSnapshotCancellation{}, false
	}
	x := held.snapshot
	result := artifact.SourceSnapshotCancellation{CaptureID: x.CaptureID, AttemptID: x.AttemptID, Request: x.Request, AcceptedExpectationDigest: artifact.Digest(x.ExpectationDigest), JoinedAt: joined.UTC().Truncate(time.Microsecond)}
	return result, result.Valid()
}
