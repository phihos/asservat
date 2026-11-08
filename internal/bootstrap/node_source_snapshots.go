package bootstrap

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/syscalls"
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
	// Each refusal names its stage in the collector log (content-free), so a
	// saved window that never starts is diagnosable from the node.
	refuse := func(reason collector.Reason, stage string) collector.Receipt {
		r.Reason = reason
		if n.log != nil {
			n.log(fmt.Sprintf("node collector: source %s snapshot %s refused at %s: %s", x.Binding.SourceID, q.SnapshotID, stage, reason))
		}
		return r
	}
	if !x.Valid() || [32]byte(q.SourceBindingDigest) != deliveryapp.SourceBindingDigest(x.Binding) || q.IssuedAt.After(now) || !now.Before(w.NotAfter) || n.upload == nil || n.takeUpload == nil {
		return refuse(collector.ReasonWorkUnknown, "work")
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
		return refuse(collector.ReasonCaptureBusy, "busy")
	}
	source := n.sources[x.Binding.SourceID]
	if source == nil {
		return refuse(collector.ReasonWorkUnknown, "source")
	}
	source.mu.Lock()
	p := source.meter.Permit()
	httpExact := source.httpConfig == nil && q.HTTP == (artifact.RecordingHTTP{})
	if h := source.httpConfig; h != nil {
		httpExact = q.HTTP == (artifact.RecordingHTTP{MaxFlows: h.MaxFlows, MaxHeaderBytes: h.MaxHeaderBytes, MaxFlowBytes: h.MaxFlowBytes, MaxTotalBytes: h.MaxTotalBytes, IdleMillis: h.IdleTimeout.Milliseconds()})
	}
	exact := httpExact && p.Binding == x.Binding && p.StartedAt.Equal(q.SourceStartedAt) && p.HardUntil.Equal(q.SourceHardUntil)
	source.mu.Unlock()
	if !exact {
		return refuse(collector.ReasonWorkUnknown, "binding")
	}
	processing, cancel := context.WithDeadline(parent, q.ProcessingUntil)
	copy, err := source.BeginWindow(processing, packets.RingWindow{From: q.T0.Add(-q.Before), Until: q.T0.Add(q.After)}, q.T0, q.MaxBytes)
	if err != nil {
		cancel()
		return refuse(collector.ReasonCaptureBusy, "window")
	}
	n.budgetMu.Lock()
	err = n.budget.ReserveFrozenWithin(q.MaxBytes, source.lowering)
	n.budgetMu.Unlock()
	if err != nil {
		copy.Close()
		cancel()
		return refuse(collector.ReasonCaptureBusy, "budget")
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
	if err := copy.Complete(n.now()); err != nil {
		n.snapshotFailed(x, "complete", err)
		n.uploadSnapshotFailure(ctx, epoch, workID, x, copy.records)
		return
	}
	coverage, pre := copy.Coverage(), copy.HistoryCoverage()
	acquiredFrom, acquiredUntil := artifact.SourceSnapshotAcquisition(artifact.SourceSnapshotCoverage{Request: q, SourceStoppedAt: coverage.SourceStoppedAt, SourceClosedAt: coverage.SourceClosedAt})
	var native []byte
	var counters packets.Counters
	var err error
	nativeType, snaplen := "", packets.Snaplen
	nativeComplete := true
	if h := copy.httpConfig; h != nil {
		nativeType, snaplen = artifact.HTTPHeadersArtifact, httpheaders.Snaplen
		native, counters, nativeComplete, err = httpheaders.EncodeSourceWindow(ctx, copy, httpheaders.Limits{MaxFlows: h.MaxFlows, MaxHeaderBytes: h.MaxHeaderBytes, MaxFlowBytes: h.MaxFlowBytes, MaxTotalBytes: h.MaxTotalBytes, IdleTimeout: h.IdleTimeout}, q.MaxBytes, acquiredFrom, acquiredUntil, coverage.Complete && !coverage.InputUnknown && !coverage.HistoryEvicted)
	} else if copy.records {
		nativeType, snaplen = artifact.SyscallRecordsArtifact, syscalls.RecordSize
		native, counters, err = encodeSyscallWindow(ctx, copy, int(q.MaxBytes), copy.maxEvents, x.Binding.PodUID, x.Binding.SourceID, acquiredFrom, acquiredUntil)
	} else {
		native, counters, err = packets.EncodeWindow(ctx, copy, int(q.MaxBytes), acquiredFrom, acquiredUntil)
	}
	if err != nil {
		n.snapshotFailed(x, "encode", err)
		n.uploadSnapshotFailure(ctx, epoch, workID, x, copy.records)
		return
	}
	defer clear(native[:cap(native)])
	// Empty unknown history is absence, not fabricated successful evidence.
	// ponytail: an empty syscall window has no bytes to upload, so even a
	// complete quiet one reports absence; add a zero-byte result if pods
	// with no syscalls in a whole window turn out to matter.
	if counters.Retained == 0 && (!coverage.Complete || copy.records) {
		n.snapshotFailed(x, "empty", fmt.Errorf("window %s..%s available from %s, stopped %s, closed %s, evicted %t, input unknown %t; source %s", coverage.Requested.From.Format(time.RFC3339Nano), coverage.Requested.Until.Format(time.RFC3339Nano), coverage.AvailableFrom.Format(time.RFC3339Nano), coverage.SourceStoppedAt.Format(time.RFC3339Nano), coverage.SourceClosedAt.Format(time.RFC3339Nano), coverage.HistoryEvicted, coverage.InputUnknown, n.sourceCounters(x.Binding.SourceID)))
		n.uploadSnapshotFailure(ctx, epoch, workID, x, copy.records)
		return
	}
	completed := n.now().UTC()
	outcome := artifact.SourceSnapshotOutcome{NativeSHA256: artifact.Digest(sha256.Sum256(native)), SourceSnapshotCoverage: artifact.SourceSnapshotCoverage{Request: q, AcceptedExpectationDigest: artifact.Digest(x.ExpectationDigest), NativeBytes: int64(len(native)), Retained: counters.Retained, OutputFull: counters.OutputFull, AvailableFrom: coverage.AvailableFrom, ObservedUntil: coverage.ObservedUntil, SourceStoppedAt: coverage.SourceStoppedAt.UTC(), SourceClosedAt: coverage.SourceClosedAt.UTC(), CompletedAt: completed, HistoryComplete: pre.Complete && !coverage.InputUnknown && !coverage.HistoryEvicted, WindowComplete: coverage.Complete && nativeComplete && counters.OutputFull == 0, HistoryEvicted: coverage.HistoryEvicted, InputUnknown: coverage.InputUnknown}}
	result := collector.PacketResult{Snapshot: &outcome, WorkID: workID, CaptureID: x.CaptureID, StartedAt: acquiredFrom, EndedAt: acquiredUntil, Seen: counters.Seen, Retained: counters.Retained, Filtered: counters.Filtered, OutputFull: counters.OutputFull, WireBytes: counters.WireBytes, CapturedBytes: int64(len(native)), Snaplen: snaplen, EngineVersion: n.version, ProgramDigest: x.Binding.ProgramDigest, NativeType: nativeType}
	if !result.Valid() {
		// Never upload an inconsistent result, but name the refusal instead
		// of ending the snapshot silently.
		n.snapshotFailed(x, "result", fmt.Errorf("inconsistent %s result: seen=%d retained=%d filtered=%d outputFull=%d bytes=%d snaplen=%d window %s..%s", nativeType, counters.Seen, counters.Retained, counters.Filtered, counters.OutputFull, len(native), snaplen, acquiredFrom.Format(time.RFC3339Nano), acquiredUntil.Format(time.RFC3339Nano)))
		return
	}
	if n.takeUpload(ctx, result.CapturedBytes) {
		uploadStarted := n.now()
		err := n.upload(ctx, epoch, result, native)
		if n.log != nil {
			n.log(fmt.Sprintf("node collector: source %s snapshot %s: %d events, %d bytes, completed %s, upload %s (%v); source %s", x.Binding.SourceID, q.SnapshotID, counters.Retained, len(native), completed.Format(time.RFC3339Nano), n.now().Sub(uploadStarted).Round(10*time.Millisecond), err, n.sourceCounters(x.Binding.SourceID)))
		}
	}
}

// A wholly absent window reports terminal failure through the existing result
// path. The connector discards this placeholder and never creates an artifact.
// The connector checks the native type before the failure, so a syscall
// source's failure carries its type (the placeholder bytes are discarded).
func (n *nodeSources) uploadSnapshotFailure(ctx context.Context, epoch, workID string, x collector.SourceSnapshot, records bool) {
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
	if x.Request.HTTP.Valid() {
		result.NativeType = artifact.HTTPHeadersArtifact
		result.Snaplen = httpheaders.Snaplen
	} else if records {
		result.NativeType = artifact.SyscallRecordsArtifact
	}
	if result.Valid() && n.takeUpload(ctx, result.CapturedBytes) {
		_ = n.upload(ctx, epoch, result, native)
	}
}

// snapshotFailed logs why a saved window reports absence; the result itself
// carries only CaptureFailed.
func (n *nodeSources) snapshotFailed(x collector.SourceSnapshot, stage string, err error) {
	if n.log != nil {
		n.log(fmt.Sprintf("node collector: source %s snapshot %s failed at %s: %v", x.Binding.SourceID, x.Request.SnapshotID, stage, err))
	}
}

// sourceCounters is the source's content-free ring and meter accounting.
func (n *nodeSources) sourceCounters(id string) string {
	n.mu.Lock()
	s := n.sources[id]
	n.mu.Unlock()
	if s == nil {
		return "gone"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.ring.State()
	out := fmt.Sprintf("seen=%d retained=%d malformed=%d evicted=%d observed=%dB closed=%t", st.Packets.Seen, st.Packets.Retained, st.Packets.Malformed, st.HistoryEvicted, s.meter.ObservedBytes(), s.closed)
	if s.httpProjector != nil {
		// Content-free cumulative projector counters (flows, stops, limits).
		out += fmt.Sprintf(" http=%+v", s.httpProjector.SourceCounters())
	}
	return out
}
