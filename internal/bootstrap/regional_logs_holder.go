package bootstrap

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type heldLogs struct {
	expectation artifact.ContextExpectation
	digest      artifact.Digest
	queued      time.Time
	expires     time.Time
	cancel      context.CancelFunc
	stop        *collector.RecordingStop
	joined      bool
	outcome     evidence.RecordingCollection
}

func (h *ConnectorRecordings) heldCountLocked() int {
	return len(h.held) + len(h.profiles) + len(h.logs)
}

func (h *ConnectorRecordings) configureLogs(ctx context.Context, root string, client *kube.SavedLogClient, pod, epoch string) {
	// The new owner can accept starts only after the previous owner's workers
	// have joined. Retain their original terminal records for collection.
	h.closeLogs()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logsContext, h.logsRoot, h.logsClient, h.logsEpoch = ctx, root, client, epoch
	h.logsWriterPod = pod
	h.logsClosing = false
	if h.logs == nil {
		h.logs = make(map[string]*heldLogs)
	}
}

// closeLogs is the owning connector's joined shutdown, not a background task.
func (h *ConnectorRecordings) closeLogs() {
	h.mu.Lock()
	h.logsClosing = true
	for _, p := range h.logs {
		if p.cancel != nil {
			p.cancel()
		}
	}
	h.mu.Unlock()
	h.logsWG.Wait()
}

func (h *ConnectorRecordings) PrepareLogs(p *objectstore.PreparedArtifact, e artifact.ContextExpectation) *preparedLogs {
	e.Logs = e.Logs.Clone()
	return &preparedLogs{holder: h, prepared: p, expectation: e}
}

func (h *ConnectorRecordings) startLogs(ctx context.Context, prepared *objectstore.PreparedArtifact, e artifact.ContextExpectation, pin artifact.PinnedPod, started, until time.Time) (time.Time, error) {
	if h == nil || ctx == nil || ctx.Err() != nil || prepared == nil || e.Validate() != nil || e.Logs == nil || pin.UID != e.PodUID || pin.NamespaceUID != e.NamespaceUID || pin.Namespace != e.Namespace || started.IsZero() {
		return time.Time{}, value.ErrInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.expireLocked(now)
	if h.logsClient == nil || h.logsContext == nil || h.logsContext.Err() != nil || h.logsClosing || h.logsEpoch == "" || !now.Before(until) || now.Before(started) || !now.Before(e.Registration.WriteUntil) || h.heldCountLocked() >= maxHeldRecordings && h.held[e.CaptureUID] == nil || h.logs[e.CaptureUID] != nil || h.profiles[e.CaptureUID] != nil {
		return time.Time{}, value.ErrUnavailable
	}
	queued := now.UTC().Truncate(time.Microsecond)
	held := &heldLogs{expectation: e, digest: evidence.ContextExpectationDigest(e), queued: queued, expires: e.Registration.WriteUntil.Add(recordingRetain), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
	if old := h.held[e.CaptureUID]; old != nil {
		if !old.cancelOnly || old.recordingStop == nil || old.digest != held.digest || old.expectation.Registration.Location.AttemptID != e.Registration.Location.AttemptID {
			return time.Time{}, value.ErrDenied
		}
		stop := *old.recordingStop
		if stop.RootID != h.logsRoot || stop.ClusterID != e.Registration.Location.ClusterID || stop.WriterEpoch != h.logsEpoch || stop.WriterPodUID != h.logsWriterPod || !stop.WriteUntil.Equal(e.Registration.WriteUntil) {
			return time.Time{}, value.ErrDenied
		}
		delete(h.held, e.CaptureUID)
		held.stop, held.joined = &stop, true
		held.outcome = h.logsCancelled(held)
		h.logs[e.CaptureUID] = held
		return queued, nil
	}
	// The accepted action lifetime starts at the original API CAS, not at
	// receipt, a retry, or a later source fetch.
	deadline := e.Registration.WriteUntil
	if actionEnd := started.Add(time.Duration(e.Logs.TimeoutMillis) * time.Millisecond); actionEnd.Before(deadline) {
		deadline = actionEnd
	}
	if !now.Before(deadline) {
		return time.Time{}, value.ErrExpired
	}
	work, cancel := context.WithDeadline(h.logsContext, deadline)
	held.cancel = cancel
	h.logs[e.CaptureUID] = held
	h.logsWG.Add(1)
	go h.runLogs(work, held, prepared, pin)
	return queued, nil
}

func (h *ConnectorRecordings) runLogs(ctx context.Context, held *heldLogs, prepared *objectstore.PreparedArtifact, pin artifact.PinnedPod) {
	defer h.logsWG.Done()
	defer held.cancel()
	e := held.expectation
	_, windowEnd, err := e.Logs.Window(e.TriggeredAt)
	if err == nil && h.now().Before(windowEnd) {
		timer := time.NewTimer(windowEnd.Sub(h.now()))
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-timer.C:
		}
		timer.Stop()
	}
	var copies artifact.Copies
	if err == nil {
		h.mu.Lock()
		reserved := h.waitStoreLocked(ctx, e.Registration.WriteUntil, maxStoringBytes)
		h.mu.Unlock()
		if reserved {
			copies, err = h.storeLogs(ctx, held, prepared, pin)
			h.mu.Lock()
			h.releaseStoreLocked(maxStoringBytes)
			h.mu.Unlock()
		} else {
			err = value.ErrUnavailable
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	held.joined = true
	stored := h.now().UTC().Truncate(time.Microsecond)
	out := evidence.RecordingCollection{State: evidence.RecordingStored, Acquired: held.queued, Completion: artifact.ContextWriterCompletion{RegistrationDigest: privacyapp.RegistrationDigest(e.Registration), ExpectationDigest: held.digest, Copies: copies, StoredAt: stored, ClosedAt: stored}}
	if err != nil || !out.Valid(e.Registration) {
		out = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "captureFailed"}
		if errors.Is(err, targets.ErrChanged) {
			out.Failure = evidence.RecordingTargetGone
			if h.log != nil {
				h.log("regional logs failed: source-changed")
			}
		}
		if held.stop != nil {
			out = h.logsCancelled(held)
		}
	}
	held.outcome = out
}

func (h *ConnectorRecordings) storeLogs(ctx context.Context, held *heldLogs, prepared *objectstore.PreparedArtifact, pin artifact.PinnedPod) (artifact.Copies, error) {
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	type completed struct {
		at  time.Time
		err error
	}
	done := make(chan completed, 1)
	go func() {
		err := captureSavedLogs(work, h.logsClient, pin, *held.expectation.Logs, held.expectation.TriggeredAt, writer, h.now)
		at := h.now().UTC().Truncate(time.Microsecond)
		_ = writer.CloseWithError(err)
		done <- completed{at, err}
	}()
	joined := false
	copies, err := prepared.StoreLogs(work, reader, held.queued, func() (time.Time, error) {
		result := <-done
		joined = true
		return result.at, result.err
	})
	_ = reader.CloseWithError(err)
	if !joined {
		cancel()
		result := <-done
		if err == nil {
			err = result.err
		}
	}
	return copies, err
}

func (h *ConnectorRecordings) logsCancelled(held *heldLogs) evidence.RecordingCollection {
	if held.stop == nil || !held.joined {
		return evidence.RecordingCollection{State: evidence.RecordingPending}
	}
	stop := held.stop
	proof := artifact.LogCancellation{CaptureID: stop.CaptureID, AttemptID: stop.AttemptID, WriterPodUID: stop.WriterPodUID, WriterEpoch: stop.WriterEpoch, ExpectationDigest: stop.ExpectationDigest, JoinedAt: h.now().UTC().Truncate(time.Microsecond)}
	return evidence.RecordingCollection{State: evidence.RecordingCancelled, LogsCancellation: &proof}
}

func (h *ConnectorRecordings) cancelLogsLocked(stop collector.RecordingStop, held *heldLogs) error {
	e := held.expectation
	if stop.RootID != h.logsRoot || stop.ClusterID != e.Registration.Location.ClusterID || stop.CaptureID != e.CaptureUID || stop.AttemptID != e.Registration.Location.AttemptID || stop.ExpectationDigest != held.digest || stop.WriterEpoch != h.logsEpoch || stop.WriterPodUID != h.logsWriterPod || !stop.WriteUntil.Equal(e.Registration.WriteUntil) || held.stop != nil && !held.stop.Equal(stop) {
		return value.ErrDenied
	}
	if held.outcome.State == evidence.RecordingStored || held.outcome.State == evidence.RecordingCancelled {
		return nil
	}
	held.stop = &stop
	if held.cancel != nil {
		held.cancel()
	}
	if held.joined {
		held.outcome = h.logsCancelled(held)
	}
	return nil
}

func (h *ConnectorRecordings) collectLogs(w fleet.APIContextWork) (evidence.RecordingCollection, bool, error) {
	held := h.logs[w.CaptureID]
	if held == nil {
		return evidence.RecordingCollection{}, false, nil
	}
	if held.expectation.Registration.Location.AttemptID != w.AttemptID || held.digest != w.ExpectationDigest {
		return evidence.RecordingCollection{}, true, value.ErrDenied
	}
	return held.outcome, true, nil
}

type preparedLogs struct {
	holder      *ConnectorRecordings
	expectation artifact.ContextExpectation
	mu          sync.Mutex
	prepared    *objectstore.PreparedArtifact
}

var _ evidence.LogsRecorder = (*preparedLogs)(nil)

func (p *preparedLogs) Close() { p.mu.Lock(); p.prepared = nil; p.mu.Unlock() }
func (p *preparedLogs) StoreContext(context.Context, []byte, time.Time, time.Time) (artifact.Copies, error) {
	return artifact.Copies{}, value.ErrUnavailable
}
func (p *preparedLogs) StartLogs(ctx context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, error) {
	p.mu.Lock()
	prepared := p.prepared
	p.prepared = nil
	p.mu.Unlock()
	if prepared == nil {
		return time.Time{}, value.ErrDenied
	}
	return p.holder.startLogs(ctx, prepared, p.expectation, pin, started, until)
}
