package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	compiler "asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-248: the connector's holder of started manual packet recordings.
//
// The start exchange prepares the attempt's keys (three wraps through the
// local key service, as for pod status) and StartRecording queues one
// packetCapture item on the target Pod's node collector. The node's result
// arrives over the node channel; the holder streams it through the ADR-244
// artifact producer (framed encryption with the wrap-only key, four
// write-only objects) and keeps only the writer completion until the hub
// collects it. Plaintext and data keys stay in this process. In memory, a
// recording holds its prepared keys until the result is stored or it
// expires; at most maxHeldRecordings are held and maxStoringBytes of results
// are encrypted at once (the connector's frozen budget).
const (
	maxHeldRecordings = 64
	maxStoringBytes   = 4 * artifact.RecordingNativeLimit
	// recordingRetain bounds how long a stored or failed outcome waits for
	// its collect after the recording's write window.
	recordingRetain = time.Minute
)

// podNodes reads the node of an exact pinned Pod (kube.ContextCollector).
type podNodes interface {
	PodNode(context.Context, artifact.PinnedPod) (string, error)
}

// recordingNodes is the node channel facet the holder uses.
type recordingNodes interface {
	NodeByName(string) (delivery.NodeView, bool)
	EnqueuePacket(string, collector.PacketCapture, time.Time) (collector.Work, error)
}

type heldRecording struct {
	argumentSource  *targets.PacketSourceObservation
	recordingStop   *collector.RecordingStop
	resultArrived   bool // original authenticated result arrived after engine return
	resultJoined    bool // result handling and local writer have returned
	storing         bool
	stopStoreWait   context.CancelFunc // only the unread FIFO wait, never an active Store
	cancelID        string
	cancelRequested bool
	cancelOnly      bool
	expectation     artifact.ContextExpectation
	digest          artifact.Digest
	prepared        *objectstore.PreparedArtifact
	nodeUID         string
	workID          string
	queued          time.Time
	expires         time.Time
	snapshot        *collector.SourceSnapshot
	outcome         evidence.RecordingCollection
	// stopPeers ends the recording's peer membership verifier (ADR-283
	// part 3); nil without Kubernetes peers.
	stopPeers context.CancelFunc
}

type ConnectorRecordings struct {
	logs                map[string]*heldLogs
	logsContext         context.Context
	logsRoot, logsEpoch string
	logsWriterPod       string
	logsClient          *kube.SavedLogClient
	logsClosing         bool
	logsWG              sync.WaitGroup
	nodes               recordingNodes
	pods                podNodes
	now                 func() time.Time
	log                 func(string)

	// after paces the peer verifiers (time.After; tests inject a clock).
	after func(time.Duration) <-chan time.Time
	wg    sync.WaitGroup

	mu                   sync.Mutex
	profileEndpoints     profileEndpointPlans
	profileAuthorization ProfileAuthorizationReader
	profiles             map[string]*heldProfile
	held                 map[string]*heldRecording // by capture ID
	storing              int64
	storeReleased        chan struct{}  // broadcast on store capacity or FIFO head change
	storeWaiters         []*storeWaiter // bounded by the 64 one-use holders
	peers                peerResolver
	verifiers            int // running peer verifiers, at most maxPeerVerifiers
}

func NewConnectorRecordings(nodes recordingNodes, pods podNodes, now func() time.Time, log func(string)) *ConnectorRecordings {
	return &ConnectorRecordings{nodes: nodes, pods: pods, now: now, log: log, after: time.After, held: map[string]*heldRecording{}}
}

// releaseStoreLocked wakes completed uploads without polling or
// reserving their working memory during acquisition. Call with h.mu held.
func (h *ConnectorRecordings) releaseStoreLocked(bytes int64) {
	h.storing -= bytes
	h.notifyStoreLocked()
}

// expireLocked drops outcomes and pending recordings past their deadline.
// A pending recording that expires keeps no keys: its PreparedArtifact is
// dropped unused (the attempt stays charged until custody cleanup).
func (h *ConnectorRecordings) expireLocked(now time.Time) {
	for id, p := range h.logs {
		if p.joined && !now.Before(p.expires) {
			delete(h.logs, id)
		}
	}
	for id, p := range h.profiles {
		if !p.storing && !now.Before(p.expires) {
			delete(h.profiles, id)
		}
	}
	for id, r := range h.held {
		if !r.storing && !now.Before(r.expires) {
			delete(h.held, id)
		}
	}
}

// PacketRecorder answers the hub's availability query (ADR-248).
func (h *ConnectorRecordings) PacketRecorder(ctx context.Context, r targets.RecorderRequest) (targets.RecorderAnswer, error) {
	if !r.Valid() {
		return targets.RecorderAnswer{}, targets.ErrInvalid
	}
	if h.nodes == nil || h.pods == nil {
		return targets.RecorderAnswer{Outcome: targets.RecorderUnavailable}, nil
	}
	name, err := h.pods.PodNode(ctx, r.Pin)
	if err != nil {
		return targets.RecorderAnswer{Outcome: targets.RecorderNoNode}, nil
	}
	mechanism := collector.MechanismPacket
	if r.Syscall {
		mechanism = collector.MechanismSyscall
	}
	v, ok := h.nodes.NodeByName(name)
	if !ok || !v.RecorderAvailable(mechanism) {
		return targets.RecorderAnswer{Outcome: targets.RecorderUnavailable}, nil
	}
	return targets.RecorderAnswer{Outcome: targets.RecorderAvailable}, nil
}

// prepare returns the prepared output of a recording expectation.
func (h *ConnectorRecordings) Prepare(prepared *objectstore.PreparedArtifact, e artifact.ContextExpectation) *preparedRecording {
	if e.Recording != nil && e.Recording.Arguments != nil {
		e.Recording = e.Recording.Clone()
	}
	return &preparedRecording{holder: h, prepared: prepared, expectation: e}
}

// start queues the recording on the Pod's node and holds the prepared keys.
func (h *ConnectorRecordings) start(ctx context.Context, p *objectstore.PreparedArtifact, e artifact.ContextExpectation, pin artifact.PinnedPod, until time.Time) (time.Time, error) {
	rec := e.Recording
	if !rec.Valid() || rec.Arguments != nil || pin.UID != e.PodUID || pin.NamespaceUID != e.NamespaceUID {
		return time.Time{}, value.ErrInvalid
	}
	name, err := h.pods.PodNode(ctx, pin)
	if err != nil {
		return time.Time{}, value.ErrUnavailable
	}
	mechanism := collector.MechanismPacket
	if rec.Kind == "syscallTrace" {
		mechanism = collector.MechanismSyscall
	}
	v, ok := h.nodes.NodeByName(name)
	if !ok || !v.RecorderAvailable(mechanism) {
		return time.Time{}, value.ErrUnavailable
	}
	work := collector.PacketCapture{CaptureID: e.CaptureUID, PodUID: e.PodUID, Duration: time.Duration(rec.DurationMillis) * time.Millisecond, MaxBytes: rec.MaxBytes}
	if s := rec.Syscalls; s != nil {
		// B3: a finite syscall metadata recording of the same Pod.
		work.Syscalls = &collector.SyscallFilter{Names: append([]string(nil), s.Names...), ErrorsOnly: s.ErrorsOnly, MaxEvents: s.MaxEvents, MaxTrackedThreads: s.MaxTrackedThreads}
		work.MaxEventsPerSecond = s.MaxEventsPerSecond
	}
	if f := rec.Filter; f != nil {
		work.Program = make([]planning.BPFInstruction, len(f.Program))
		for i, ins := range f.Program {
			work.Program[i] = planning.BPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
		}
		work.ProgramDigest = [32]byte(compiler.FilterProgramDigest(work.Program))
	}
	// ADR-283 part 3: frozen Kubernetes peers must resolve to exactly the
	// reviewed members before the node is asked to record.
	frozen, peered, err := compiler.FrozenRecordingPeers(rec)
	if err != nil {
		return time.Time{}, value.ErrInvalid
	}
	var confirmed time.Time
	if peered {
		if confirmed, err = h.confirmPeersAtStart(ctx, frozen); err != nil {
			h.log("connector recording " + e.CaptureUID + " refused at start: " + err.Error())
			return time.Time{}, err
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.expireLocked(now)
	if _, exists := h.held[e.CaptureUID]; exists || h.logs[e.CaptureUID] != nil || h.heldCountLocked() >= maxHeldRecordings || !now.Before(until) {
		return time.Time{}, value.ErrUnavailable
	}
	if peered && h.verifiers >= maxPeerVerifiers {
		return time.Time{}, targets.ErrPeerVerifierBusy
	}
	if peered && !now.Before(confirmed.Add(frozen.MaxStaleness)) {
		return time.Time{}, targets.ErrPeersStale
	}
	// The node may start until the earlier of the committed start's end
	// plus its start allowance and the write window.
	startBy := now.Add(collector.PacketCaptureStartWithin)
	if !startBy.Before(e.Registration.WriteUntil) {
		return time.Time{}, value.ErrExpired
	}
	w, err := h.nodes.EnqueuePacket(v.Identity.NodeUID, work, startBy)
	if err != nil {
		return time.Time{}, value.ErrUnavailable
	}
	queued := now.UTC().Truncate(time.Microsecond)
	held := &heldRecording{expectation: e, digest: evidence.ContextExpectationDigest(e), prepared: p, nodeUID: v.Identity.NodeUID, workID: w.ID, queued: queued,
		expires: e.Registration.WriteUntil.Add(recordingRetain), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
	h.held[e.CaptureUID] = held
	if peered {
		// The verifier outlives the start exchange; it ends with the
		// recording window, the node's result or a stop.
		verify, stop := context.WithCancel(context.Background())
		held.stopPeers = stop
		h.verifiers++
		h.wg.Add(1)
		go h.verifyPeers(verify, held, peerVerifier{resolve: h.peers, now: h.now, after: h.after, frozen: frozen}, confirmed, startBy.Add(work.Duration))
		h.log(fmt.Sprintf("connector recording %s verifies %d frozen peer members every %s", e.CaptureUID, len(frozen.Resolution.Members), peerVerifyInterval))
	}
	h.log("connector recording " + e.CaptureUID + " queued on node " + name)
	return queued, nil
}

// DeliverPacket is the node channel's sink (delivery.PacketSink).
func (h *ConnectorRecordings) DeliverPacket(ctx context.Context, node collector.Identity, r collector.PacketResult, pcapng io.Reader) error {
	h.mu.Lock()
	h.expireLocked(h.now())
	held := h.held[r.CaptureID]
	if held == nil || held.workID != r.WorkID || held.nodeUID != node.NodeUID || held.outcome.State != evidence.RecordingPending || held.prepared == nil {
		h.mu.Unlock()
		_, _ = io.Copy(io.Discard, pcapng)
		return value.ErrConflict
	}
	nativeType := r.NativeType
	if nativeType == "" {
		nativeType = artifact.PCAPNGArtifact
	}
	if held.snapshot != nil {
		x := held.snapshot
		if r.Snapshot == nil || nativeType != held.expectation.NativeType || node.BootID != x.Binding.BootID || node.PodUID != x.Binding.CollectorPodUID || node.Epoch != x.Binding.CollectorEpoch || r.ProgramDigest != x.Binding.ProgramDigest || !r.Snapshot.Request.Equal(x.Request) || r.Snapshot.AcceptedExpectationDigest != artifact.Digest(x.ExpectationDigest) {
			h.mu.Unlock()
			_, _ = io.Copy(io.Discard, pcapng)
			return value.ErrDenied
		}
	} else if r.Snapshot != nil || nativeType != held.expectation.NativeType {
		h.mu.Unlock()
		_, _ = io.Copy(io.Discard, pcapng)
		return value.ErrDenied
	}
	if source := held.argumentSource; source != nil {
		if node.BootID != source.BootID || node.PodUID != source.CollectorPodUID || node.Epoch != source.CollectorEpoch || r.Failure == "" && (r.StartedAt.Before(held.queued) || r.EndedAt.Before(r.StartedAt)) {
			h.mu.Unlock()
			_, _ = io.Copy(io.Discard, pcapng)
			return value.ErrDenied
		}
	}
	if held.snapshot == nil {
		// The original node result is the only evidence that a manual
		// recording's engine returned; a Stop joins only after its handling.
		held.resultArrived = true
		defer func() {
			h.mu.Lock()
			held.resultJoined = true
			h.mu.Unlock()
		}()
	}
	if r.Failure != "" {
		if held.stopPeers != nil {
			held.stopPeers()
		}
		held.prepared, held.outcome = nil, evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "captureFailed"}
		h.mu.Unlock()
		_, _ = io.Copy(io.Discard, pcapng)
		h.log("connector recording " + r.CaptureID + " failed on the node: " + string(r.Failure))
		return nil
	}
	// Claim this body before entering the shared FIFO. A later delivery cannot
	// replace it, including after cancellation or an expired wait.
	held.storing = true
	prepared, e := held.prepared, held.expectation
	held.prepared = nil
	storeCtx, cancelStore := context.WithDeadline(ctx, e.Registration.WriteUntil)
	defer cancelStore()
	if held.stopPeers != nil {
		held.stopPeers()
	}
	held.stopStoreWait = cancelStore
	if held.cancelRequested {
		cancelStore()
	}
	admitted := h.waitStoreLocked(storeCtx, e.Registration.WriteUntil, r.CapturedBytes)
	held.stopStoreWait = nil // active Store keeps its existing stored-wins lifecycle
	if !admitted {
		held.storing = false
		held.outcome = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "storeUnconfirmed"}
		h.mu.Unlock()
		return value.ErrUnavailable
	}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.releaseStoreLocked(r.CapturedBytes)
		held.storing = false
		h.mu.Unlock()
	}()
	// Finite recordings cannot predate queueing. An independently admitted
	// source snapshot retains its original acquisition window instead. Argument
	// records retain the exact header/footer interval, validated above; changing
	// nanoseconds here would disagree with the native bytes.
	started, completed := r.StartedAt.UTC(), r.EndedAt.UTC()
	if held.snapshot == nil && held.argumentSource == nil {
		started = started.Truncate(time.Microsecond)
		if started.Before(held.queued) {
			started = held.queued
		}
		completed = completed.Truncate(time.Microsecond)
		if completed.Before(started) {
			completed = started
		}
	}
	var copies artifact.Copies
	var err error
	storeStarted := h.now()
	if held.snapshot != nil {
		copies, err = prepared.StoreSnapshot(storeCtx, pcapng, started, completed, *r.Snapshot)
	} else {
		copies, err = prepared.Store(storeCtx, pcapng, started, completed)
	}
	stored := h.now().UTC().Truncate(time.Microsecond)
	outcome := evidence.RecordingCollection{State: evidence.RecordingStored, Acquired: held.queued,
		Completion: artifact.ContextWriterCompletion{RegistrationDigest: privacyapp.RegistrationDigest(e.Registration), ExpectationDigest: held.digest, Copies: copies, StoredAt: stored, ClosedAt: stored}}
	if held.snapshot != nil && err == nil {
		coverage := r.Snapshot.SourceSnapshotCoverage
		outcome.SnapshotCoverage = &coverage
		final, projectionErr := artifact.ProjectSourceSnapshotCoverage(e, held.digest, coverage)
		if projectionErr != nil {
			err = projectionErr
		} else {
			outcome.Completion.ExpectationDigest = evidence.ContextExpectationDigest(final)
		}
	}
	if err != nil || !outcome.Valid(e.Registration) {
		outcome = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "storeUnconfirmed"}
		reason := "invalid outcome"
		if err != nil {
			reason = err.Error() // fixed artifact error classes, no content
		}
		h.log("connector recording " + r.CaptureID + " store unconfirmed: " + reason)
	} else {
		h.log(fmt.Sprintf("connector recording %s stored: %d native bytes in %s, window end %s, processing until %s", r.CaptureID, r.CapturedBytes, h.now().Sub(storeStarted).Round(10*time.Millisecond), completed.Format(time.RFC3339Nano), held.expectation.Registration.WriteUntil.Format(time.RFC3339Nano)))
	}
	h.mu.Lock()
	held.outcome = outcome
	h.mu.Unlock()
	if err != nil {
		return value.ErrUnavailable
	}
	return nil
}

// Collect answers the hub's collect for the work's capture.
func (h *ConnectorRecordings) Collect(w fleet.APIContextWork) (evidence.RecordingCollection, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expireLocked(h.now())
	if out, ok, err := h.collectLogs(w); ok {
		return out, err
	}
	if out, ok, err := h.collectProfile(w); ok {
		return out, err
	}
	held := h.held[w.CaptureID]
	if held == nil || held.expectation.Registration.Location.AttemptID != w.AttemptID || held.digest != w.ExpectationDigest {
		return evidence.RecordingCollection{}, value.ErrUnavailable
	}
	if held.cancelRequested && held.outcome.State != evidence.RecordingStored {
		if !held.storing {
			if receipt, ok := h.recordingCancellation(held); ok {
				held.outcome = evidence.RecordingCollection{State: evidence.RecordingCancelled, RecordingCancellation: &receipt}
				return held.outcome, nil
			}
			if receipt, ok := h.snapshotCancellation(held); ok {
				held.outcome = evidence.RecordingCollection{State: evidence.RecordingCancelled, SnapshotCancellation: &receipt}
				return held.outcome, nil
			}
		}
		return evidence.RecordingCollection{State: evidence.RecordingPending}, nil
	}
	return held.outcome, nil
}

// preparedRecording is the regional prepared output of a recording.
type preparedRecording struct {
	holder      *ConnectorRecordings
	expectation artifact.ContextExpectation
	mu          sync.Mutex
	prepared    *objectstore.PreparedArtifact
}

var (
	_ evidence.PreparedContext       = (*preparedRecording)(nil)
	_ evidence.ContextRecorder       = (*preparedRecording)(nil)
	_ evidence.PolicyContextRecorder = (*preparedRecording)(nil)
)

func (p *preparedRecording) StoreContext(context.Context, []byte, time.Time, time.Time) (artifact.Copies, error) {
	return artifact.Copies{}, value.ErrUnavailable // a recording is stored when the node delivers
}

// Close drops the keys unless the holder took them.
func (p *preparedRecording) Close() {
	p.mu.Lock()
	p.prepared = nil
	p.mu.Unlock()
}

func (p *preparedRecording) StartRecording(ctx context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, error) {
	// The legacy operation carries no committed input permit. Refuse before
	// transferring prepared ownership; only the future typed policy start may
	// carry a current exact source and the original SQL observation reservation.
	if p.expectation.Recording != nil && p.expectation.Recording.Arguments != nil || compiler.MeteredRecording(p.expectation.Recording) {
		return time.Time{}, value.ErrUnavailable
	}
	p.mu.Lock()
	prepared := p.prepared
	p.prepared = nil
	p.mu.Unlock()
	if prepared == nil {
		return time.Time{}, value.ErrDenied
	}
	return p.holder.start(ctx, prepared, p.expectation, pin, until)
}

// noJournal refuses streaming steps: a recording never exceeds one frame,
// so the producer never asks (ADR-248: the connector holds no SQL journal).
type noJournal struct{}

func (noJournal) AdvanceStreaming(context.Context, artifact.StreamingPlan, artifact.StreamingStep) (artifact.StreamingState, bool, error) {
	return artifact.StreamingState{}, false, errors.New("streaming journal unavailable on the connector")
}

// StartPolicyRecording consumes the original receipt only after all immutable
// preflight checks. The expected-source queue rechecks the same facts against
// its independently authenticated live node entry under the queue mutex.
func (p *preparedRecording) StartPolicyRecording(ctx context.Context, pin artifact.PinnedPod, started, until time.Time, source targets.PacketSourceObservation, permit collector.ObservationPermit) (time.Time, error) {
	h, e := p.holder, p.expectation
	r, b := e.Recording, permit.Binding
	now := h.now()
	if ctx == nil || ctx.Err() != nil || !source.Valid(now) || !permit.ValidFinite(now) || !now.Before(until) || started.After(now) || started.Before(permit.StartedAt) || pin.UID != e.PodUID || pin.NamespaceUID != e.NamespaceUID || source.PodUID != e.PodUID || !r.Valid() || r.Arguments != nil || !compiler.MeteredRecording(r) || b.CaptureID != e.CaptureUID || b.ActionID != e.ActionID || b.PodUID != e.PodUID || b.NodeUID != source.NodeUID || b.BootID != source.BootID || b.CollectorPodUID != source.CollectorPodUID || b.CollectorEpoch != source.CollectorEpoch || b.ExpectationDigest != [32]byte(evidence.ContextExpectationDigest(e)) || permit.Duration != time.Duration(r.DurationMillis)*time.Millisecond || permit.SessionUntil.After(e.Registration.WriteUntil) {
		return time.Time{}, value.ErrDenied
	}
	work := collector.PacketCapture{CaptureID: e.CaptureUID, PodUID: e.PodUID, Duration: permit.Duration, MaxBytes: r.MaxBytes, Observation: &permit}
	work.Program = make([]planning.BPFInstruction, len(r.Filter.Program))
	for i, ins := range r.Filter.Program {
		work.Program[i] = planning.BPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	work.ProgramDigest = [32]byte(compiler.FilterProgramDigest(work.Program))
	if r.Profile == "rawPackets" {
		work.Raw = &collector.RawPrefix{Snaplen: r.Snaplen}
		if c := r.ProtocolSnaplen; c != nil {
			work.Raw.TCP, work.Raw.UDP, work.Raw.ICMP = c.TCP, c.UDP, c.ICMP
		}
	}
	if h := r.HTTP; r.Profile == "httpHeaders" && h != nil {
		// ADR-282: frames are read at the fixed engine snaplen and projected
		// on the node within the accepted parser bounds.
		work.Raw = &collector.RawPrefix{Snaplen: r.Snaplen}
		work.HTTP = &collector.HTTPProjection{MaxFlows: h.MaxFlows, MaxHeaderBytes: h.MaxHeaderBytes, MaxFlowBytes: h.MaxFlowBytes, MaxTotalBytes: h.MaxTotalBytes, IdleTimeout: time.Duration(h.IdleMillis) * time.Millisecond}
	}
	if work.ProgramDigest != b.ProgramDigest || packets.CheckPrefixProgram(work.Program) != nil || !work.Valid() {
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
	if ctx.Err() != nil || !source.Valid(now) || !permit.ValidFinite(now) || !now.Before(until) || h.heldCountLocked() >= maxHeldRecordings {
		return time.Time{}, value.ErrUnavailable
	}
	if _, exists := h.held[e.CaptureUID]; exists || h.logs[e.CaptureUID] != nil {
		return time.Time{}, value.ErrUnavailable
	}
	prepared := p.prepared
	p.prepared = nil // entering the queue effect is single-use, including unknown replies
	w, err := queue.EnqueuePacketExpected(ctx, source, work, permit.StartBy)
	if err != nil {
		return time.Time{}, value.ErrUnavailable
	}
	queued := now.UTC().Truncate(time.Microsecond)
	h.held[e.CaptureUID] = &heldRecording{expectation: e, digest: evidence.ContextExpectationDigest(e), prepared: prepared, nodeUID: source.NodeUID, workID: w.ID, queued: queued, expires: e.Registration.WriteUntil.Add(recordingRetain), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
	return queued, nil
}
