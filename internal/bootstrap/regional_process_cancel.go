package bootstrap

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"context"
	"time"
)

func (h *ConnectorRecordings) CancelProcesses(ctx context.Context, stop collector.ProcessStop) error {
	if ctx == nil || ctx.Err() != nil || !stop.Valid() {
		return value.ErrInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.expireLocked(now)
	if !now.Before(stop.WriteUntil.Add(recordingRetain)) {
		return value.ErrExpired
	}
	p := h.processes[stop.CaptureID]
	if p == nil {
		// The same process has not queued this attempt. Keep a bounded tombstone
		// so a start already in transit cannot follow this restrictive request.
		if h.heldCountLocked() >= maxHeldRecordings {
			return value.ErrUnavailable
		}
		if h.processes == nil {
			h.processes = map[string]*heldProcesses{}
		}
		p = &heldProcesses{digest: stop.ExpectationDigest, expires: stop.WriteUntil.Add(recordingRetain), stop: &stop}
		p.outcome = h.processesCancelled(p)
		h.processes[stop.CaptureID] = p
		return nil
	}
	if p.digest != stop.ExpectationDigest || p.stop != nil && !p.stop.Equal(stop) || p.stop == nil && p.expectation.Registration.Location.AttemptID != stop.AttemptID {
		return value.ErrDenied
	}
	if p.outcome.State == evidence.RecordingStored || p.outcome.State == evidence.RecordingCancelled {
		return nil
	}
	p.stop = &stop
	if p.outcome.State == evidence.RecordingFailed {
		p.outcome = h.processesCancelled(p)
		return nil
	}
	if p.stopStore != nil {
		p.stopStore()
		// Also stop the original node upload; no receipt is issued until its
		// reader and writer have joined.
	}
	queue, ok := h.nodes.(interface {
		EnqueueProcessCancel(context.Context, string, string, string, time.Time) (collector.Work, error)
	})
	if !ok {
		return value.ErrUnavailable
	}
	until := now.Add(5 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(until) {
		until = end
	}
	_, err := queue.EnqueueProcessCancel(ctx, p.node.NodeUID, stop.CaptureID, p.workID, until)
	return err
}
func (h *ConnectorRecordings) processesCancelled(p *heldProcesses) evidence.RecordingCollection {
	stop := p.stop
	return evidence.RecordingCollection{State: evidence.RecordingCancelled, ProcessesCancellation: &artifact.ProcessCancellation{CaptureID: stop.CaptureID, AttemptID: stop.AttemptID, WriterPodUID: stop.WriterPodUID, WriterEpoch: stop.WriterEpoch, ExpectationDigest: stop.ExpectationDigest, JoinedAt: h.now().UTC().Truncate(time.Microsecond)}}
}
