package bootstrap

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

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
	expectation artifact.ContextExpectation
	digest      artifact.Digest
	prepared    *objectstore.PreparedArtifact
	nodeUID     string
	workID      string
	queued      time.Time
	expires     time.Time
	outcome     evidence.RecordingCollection
}

type ConnectorRecordings struct {
	nodes recordingNodes
	pods  podNodes
	now   func() time.Time
	log   func(string)

	mu      sync.Mutex
	held    map[string]*heldRecording // by capture ID
	storing int64
}

func NewConnectorRecordings(nodes recordingNodes, pods podNodes, now func() time.Time, log func(string)) *ConnectorRecordings {
	return &ConnectorRecordings{nodes: nodes, pods: pods, now: now, log: log, held: map[string]*heldRecording{}}
}

// expireLocked drops outcomes and pending recordings past their deadline.
// A pending recording that expires keeps no keys: its PreparedArtifact is
// dropped unused (the attempt stays charged until custody cleanup).
func (h *ConnectorRecordings) expireLocked(now time.Time) {
	for id, r := range h.held {
		if !now.Before(r.expires) {
			delete(h.held, id)
		}
	}
}

// PacketRecorder answers the hub's availability query (ADR-248).
func (h *ConnectorRecordings) PacketRecorder(ctx context.Context, r targets.RecorderRequest) (targets.RecorderAnswer, error) {
	if !r.Valid() {
		return targets.RecorderAnswer{}, targets.ErrInvalid
	}
	name, err := h.pods.PodNode(ctx, r.Pin)
	if err != nil {
		return targets.RecorderAnswer{Outcome: targets.RecorderNoNode}, nil
	}
	v, ok := h.nodes.NodeByName(name)
	if !ok || !v.PacketRecorderAvailable() {
		return targets.RecorderAnswer{Outcome: targets.RecorderUnavailable}, nil
	}
	return targets.RecorderAnswer{Outcome: targets.RecorderAvailable}, nil
}

// prepare returns the prepared output of a recording expectation.
func (h *ConnectorRecordings) Prepare(prepared *objectstore.PreparedArtifact, e artifact.ContextExpectation) *preparedRecording {
	return &preparedRecording{holder: h, prepared: prepared, expectation: e}
}

// start queues the recording on the Pod's node and holds the prepared keys.
func (h *ConnectorRecordings) start(ctx context.Context, p *objectstore.PreparedArtifact, e artifact.ContextExpectation, pin artifact.PinnedPod, until time.Time) (time.Time, error) {
	rec := e.Recording
	if !rec.Valid() || pin.UID != e.PodUID || pin.NamespaceUID != e.NamespaceUID {
		return time.Time{}, value.ErrInvalid
	}
	name, err := h.pods.PodNode(ctx, pin)
	if err != nil {
		return time.Time{}, value.ErrUnavailable
	}
	v, ok := h.nodes.NodeByName(name)
	if !ok || !v.PacketRecorderAvailable() {
		return time.Time{}, value.ErrUnavailable
	}
	work := collector.PacketCapture{CaptureID: e.CaptureUID, PodUID: e.PodUID, Duration: time.Duration(rec.DurationMillis) * time.Millisecond, MaxBytes: rec.MaxBytes}
	if f := rec.Filter; f != nil {
		work.Program = make([]planning.BPFInstruction, len(f.Program))
		for i, ins := range f.Program {
			work.Program[i] = planning.BPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
		}
		work.ProgramDigest = [32]byte(compiler.FilterProgramDigest(work.Program))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.expireLocked(now)
	if _, exists := h.held[e.CaptureUID]; exists || len(h.held) >= maxHeldRecordings || !now.Before(until) {
		return time.Time{}, value.ErrUnavailable
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
	h.held[e.CaptureUID] = &heldRecording{expectation: e, digest: evidence.ContextExpectationDigest(e), prepared: p, nodeUID: v.Identity.NodeUID, workID: w.ID, queued: queued,
		expires: e.Registration.WriteUntil.Add(recordingRetain), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
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
	if r.Failure != "" {
		held.prepared, held.outcome = nil, evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "captureFailed"}
		h.mu.Unlock()
		_, _ = io.Copy(io.Discard, pcapng)
		h.log("connector recording " + r.CaptureID + " failed on the node: " + string(r.Failure))
		return nil
	}
	if h.storing+r.CapturedBytes > maxStoringBytes {
		h.mu.Unlock()
		_, _ = io.Copy(io.Discard, pcapng)
		return value.ErrUnavailable
	}
	h.storing += r.CapturedBytes
	prepared, e := held.prepared, held.expectation
	held.prepared = nil // single use, also after a failed store
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.storing -= r.CapturedBytes
		h.mu.Unlock()
	}()
	// The manifest's acquisition interval is the node's recording interval,
	// never before the queue instant.
	started := r.StartedAt.UTC().Truncate(time.Microsecond)
	if started.Before(held.queued) {
		started = held.queued
	}
	completed := r.EndedAt.UTC().Truncate(time.Microsecond)
	if completed.Before(started) {
		completed = started
	}
	copies, err := prepared.Store(ctx, pcapng, started, completed)
	stored := h.now().UTC().Truncate(time.Microsecond)
	outcome := evidence.RecordingCollection{State: evidence.RecordingStored, Acquired: held.queued,
		Completion: artifact.ContextWriterCompletion{RegistrationDigest: privacyapp.RegistrationDigest(e.Registration), ExpectationDigest: held.digest, Copies: copies, StoredAt: stored, ClosedAt: stored}}
	if err != nil || !outcome.Valid(e.Registration) {
		outcome = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "storeUnconfirmed"}
		h.log("connector recording " + r.CaptureID + " store unconfirmed")
	} else {
		h.log("connector recording " + r.CaptureID + " stored")
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
	held := h.held[w.CaptureID]
	if held == nil || held.expectation.Registration.Location.AttemptID != w.AttemptID || held.digest != w.ExpectationDigest {
		return evidence.RecordingCollection{}, value.ErrUnavailable
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
	if r := p.expectation.Recording; r != nil && r.Filter != nil && compiler.RawBytePredicate(r.Filter.Expression) {
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
	if ctx == nil || ctx.Err() != nil || !source.Valid(now) || !permit.ValidFinite(now) || !now.Before(until) || started.After(now) || started.Before(permit.StartedAt) || pin.UID != e.PodUID || pin.NamespaceUID != e.NamespaceUID || source.PodUID != e.PodUID || r == nil || !r.Valid() || r.Filter == nil || !compiler.RawBytePredicate(r.Filter.Expression) || b.CaptureID != e.CaptureUID || b.ActionID != e.ActionID || b.PodUID != e.PodUID || b.NodeUID != source.NodeUID || b.BootID != source.BootID || b.CollectorPodUID != source.CollectorPodUID || b.CollectorEpoch != source.CollectorEpoch || b.ExpectationDigest != [32]byte(evidence.ContextExpectationDigest(e)) || permit.Duration != time.Duration(r.DurationMillis)*time.Millisecond || permit.SessionUntil.After(e.Registration.WriteUntil) {
		return time.Time{}, value.ErrDenied
	}
	work := collector.PacketCapture{CaptureID: e.CaptureUID, PodUID: e.PodUID, Duration: permit.Duration, MaxBytes: r.MaxBytes, Observation: &permit}
	work.Program = make([]planning.BPFInstruction, len(r.Filter.Program))
	for i, ins := range r.Filter.Program {
		work.Program[i] = planning.BPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	work.ProgramDigest = [32]byte(compiler.FilterProgramDigest(work.Program))
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
	if ctx.Err() != nil || !source.Valid(now) || !permit.ValidFinite(now) || !now.Before(until) || len(h.held) >= maxHeldRecordings {
		return time.Time{}, value.ErrUnavailable
	}
	if _, exists := h.held[e.CaptureUID]; exists {
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
