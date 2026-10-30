package bootstrap

import (
	"context"
	"crypto/sha256"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

type nodeSourceSnapshot struct {
	work      collector.SourceSnapshot
	cancel    context.CancelFunc
	joined    bool
	cancelled bool
	done      chan struct{}
}

// snapshotLocked runs with the manager lock held. Registration and the original
// pre-copy happen before scheduling; neither replay nor a later source arm can
// substitute another source or a newer window.
func (n *nodeSources) snapshotLocked(parent context.Context, epoch string, w collector.Work, r collector.Receipt) collector.Receipt {
	x := *w.Snapshot
	q := x.Request
	now := n.now()
	if !x.Valid() || [32]byte(q.SourceBindingDigest) != deliveryapp.SourceBindingDigest(x.Binding) || q.IssuedAt.After(now) || !now.Before(w.NotAfter) || n.upload == nil || n.takeUpload == nil {
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	for id, s := range n.snapshots {
		if s.joined && !now.Before(s.work.Request.StartBy) {
			delete(n.snapshots, id)
		}
	}
	if old := n.snapshots[q.SnapshotID]; old != nil {
		if old.work.Equal(x) && !old.cancelled {
			r.Outcome, r.Reason = collector.OutcomeAccepted, ""
		}
		return r
	}
	if len(n.snapshots) >= collector.MaxQueuedWork {
		r.Reason = collector.ReasonCaptureBusy
		return r
	}
	source := n.sources[x.Binding.SourceID]
	if source == nil {
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	source.mu.Lock()
	p := source.meter.Permit()
	exact := p.Binding == x.Binding && p.StartedAt.Equal(q.SourceStartedAt) && p.HardUntil.Equal(q.SourceHardUntil)
	source.mu.Unlock()
	if !exact {
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	processing, cancel := context.WithDeadline(parent, q.ProcessingUntil)
	copy, err := source.BeginWindow(processing, packets.RingWindow{From: q.T0.Add(-q.Before), Until: q.T0.Add(q.After)}, q.T0, q.MaxBytes)
	if err != nil {
		cancel()
		r.Reason = collector.ReasonCaptureBusy
		return r
	}
	n.budgetMu.Lock()
	err = n.budget.ReserveFrozenWithin(q.MaxBytes, source.lowering)
	n.budgetMu.Unlock()
	if err != nil {
		copy.Close()
		cancel()
		r.Reason = collector.ReasonCaptureBusy
		return r
	}
	if n.snapshots == nil {
		n.snapshots = make(map[string]*nodeSourceSnapshot)
	}
	owned := &nodeSourceSnapshot{work: x, cancel: cancel, done: make(chan struct{})}
	n.snapshots[q.SnapshotID] = owned
	n.snapshotWG.Add(1)
	go n.runSnapshot(processing, epoch, w.ID, owned, copy)
	r.Outcome, r.Reason = collector.OutcomeAccepted, ""
	return r
}

func (n *nodeSources) runSnapshot(ctx context.Context, epoch, workID string, owned *nodeSourceSnapshot, copy *packetSourceSnapshot) {
	defer n.snapshotWG.Done()
	x, q := owned.work, owned.work.Request
	defer func() {
		owned.cancel()
		copy.Close()
		n.budgetMu.Lock()
		_ = n.budget.ReleaseFrozen(q.MaxBytes)
		n.budgetMu.Unlock()
		n.mu.Lock()
		owned.joined = true
		close(owned.done)
		n.mu.Unlock()
	}()
	end := q.T0.Add(q.After)
	if wait := end.Sub(n.now()); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
	if copy.Complete(n.now()) != nil {
		n.uploadSnapshotFailure(ctx, epoch, workID, x)
		return
	}
	coverage, pre := copy.Coverage(), copy.HistoryCoverage()
	acquiredFrom, acquiredUntil := artifact.SourceSnapshotAcquisition(artifact.SourceSnapshotCoverage{Request: q, SourceStoppedAt: coverage.SourceStoppedAt, SourceClosedAt: coverage.SourceClosedAt})
	native, counters, err := packets.EncodeWindow(ctx, copy, int(q.MaxBytes), acquiredFrom, acquiredUntil)
	if err != nil {
		n.uploadSnapshotFailure(ctx, epoch, workID, x)
		return
	}
	defer clear(native[:cap(native)])
	// Empty unknown history is absence, not fabricated successful evidence.
	if counters.Retained == 0 && !coverage.Complete {
		n.uploadSnapshotFailure(ctx, epoch, workID, x)
		return
	}
	completed := n.now().UTC()
	outcome := artifact.SourceSnapshotOutcome{NativeSHA256: artifact.Digest(sha256.Sum256(native)), SourceSnapshotCoverage: artifact.SourceSnapshotCoverage{Request: q, AcceptedExpectationDigest: artifact.Digest(x.ExpectationDigest), NativeBytes: int64(len(native)), Retained: counters.Retained, OutputFull: counters.OutputFull, AvailableFrom: coverage.AvailableFrom, ObservedUntil: coverage.ObservedUntil, SourceStoppedAt: coverage.SourceStoppedAt.UTC(), SourceClosedAt: coverage.SourceClosedAt.UTC(), CompletedAt: completed, HistoryComplete: pre.Complete && !coverage.InputUnknown && !coverage.HistoryEvicted, WindowComplete: coverage.Complete && counters.OutputFull == 0, HistoryEvicted: coverage.HistoryEvicted, InputUnknown: coverage.InputUnknown}}
	result := collector.PacketResult{Snapshot: &outcome, WorkID: workID, CaptureID: x.CaptureID, StartedAt: acquiredFrom, EndedAt: acquiredUntil, Seen: counters.Seen, Retained: counters.Retained, OutputFull: counters.OutputFull, WireBytes: counters.WireBytes, CapturedBytes: int64(len(native)), Snaplen: packets.Snaplen, EngineVersion: n.version, ProgramDigest: x.Binding.ProgramDigest}
	if result.Valid() && n.takeUpload(ctx, result.CapturedBytes) {
		_ = n.upload(ctx, epoch, result, native)
	}
}

// A wholly absent window reports terminal failure through the existing result
// path. The connector discards this placeholder and never creates an artifact.
func (n *nodeSources) uploadSnapshotFailure(ctx context.Context, epoch, workID string, x collector.SourceSnapshot) {
	if ctx.Err() != nil {
		return
	}
	started, ended := artifact.SourceSnapshotAnchor(x.Request), n.now().UTC().Truncate(time.Microsecond)
	if ended.Before(started) {
		return
	}
	native := emptyCapture(started, ended)
	if native == nil {
		return
	}
	defer clear(native[:cap(native)])
	outcome := artifact.SourceSnapshotOutcome{NativeSHA256: artifact.Digest(sha256.Sum256(native)), SourceSnapshotCoverage: artifact.SourceSnapshotCoverage{Request: x.Request, AcceptedExpectationDigest: artifact.Digest(x.ExpectationDigest), NativeBytes: int64(len(native)), CompletedAt: ended}}
	result := collector.PacketResult{Snapshot: &outcome, WorkID: workID, CaptureID: x.CaptureID, StartedAt: started, EndedAt: ended, CapturedBytes: int64(len(native)), Snaplen: packets.Snaplen, EngineVersion: n.version, ProgramDigest: x.Binding.ProgramDigest, Failure: collector.ReasonCaptureFailed}
	if result.Valid() && n.takeUpload(ctx, result.CapturedBytes) {
		_ = n.upload(ctx, epoch, result, native)
	}
}
