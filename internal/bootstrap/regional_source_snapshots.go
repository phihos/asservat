package bootstrap

import (
	"context"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
)

var _ evidence.SourceSnapshotRecorder = (*preparedRecording)(nil)

func (p *preparedRecording) StartSourceSnapshot(ctx context.Context, x collector.SourceSnapshot) (time.Time, error) {
	h, e := p.holder, p.expectation
	nodeMatches := e.ExecutionClass == artifact.ContextAPIExecution && e.NodeUID == "" && e.NodeBootID == "" || e.ExecutionClass == artifact.ContextNodeExecution && e.NodeUID == x.Binding.NodeUID && e.NodeBootID == x.Binding.BootID
	if ctx == nil || ctx.Err() != nil || !x.Valid() || e.Snapshot == nil || !e.Snapshot.Equal(x.Request) || e.CaptureUID != x.CaptureID || e.Registration.Location.AttemptID != x.AttemptID || e.PodUID != x.Binding.PodUID || !nodeMatches || e.ActionID != x.Binding.ActionID || e.Snapshot.SourceBindingDigest != artifact.Digest(delivery.SourceBindingDigest(x.Binding)) || evidence.ContextExpectationDigest(e) != artifact.Digest(x.ExpectationDigest) || !h.now().Before(x.Request.StartBy) {
		return time.Time{}, value.ErrDenied
	}
	queue, ok := h.nodes.(interface {
		EnqueueSourceSnapshot(context.Context, collector.SourceSnapshot) (collector.Work, error)
	})
	if !ok {
		return time.Time{}, value.ErrUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.expireLocked(now)
	if p.prepared == nil || len(h.held) >= maxHeldRecordings || h.held[x.CaptureID] != nil || ctx.Err() != nil || !now.Before(x.Request.StartBy) {
		return time.Time{}, value.ErrUnavailable
	}
	prepared := p.prepared
	p.prepared = nil
	w, err := queue.EnqueueSourceSnapshot(ctx, x)
	if err != nil {
		return time.Time{}, value.ErrUnavailable
	}
	queued := now.UTC().Truncate(time.Microsecond)
	h.held[x.CaptureID] = &heldRecording{snapshot: &x, expectation: e, digest: evidence.ContextExpectationDigest(e), prepared: prepared, nodeUID: x.Binding.NodeUID, workID: w.ID, queued: queued, expires: e.Registration.WriteUntil.Add(recordingRetain), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
	return queued, nil
}
