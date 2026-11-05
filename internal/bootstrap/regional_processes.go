package bootstrap

import (
	"bytes"
	"context"
	"io"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	processcodec "asservat.local/asservat/internal/adapters/processes"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	compiler "asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
)

type processNodes interface {
	NodeByName(string) (delivery.NodeView, bool)
	EnqueueProcesses(context.Context, collector.ProcessCapture, time.Time) (collector.Work, error)
}
type heldProcesses struct {
	expectation     artifact.ContextExpectation
	digest          artifact.Digest
	prepared        *objectstore.PreparedArtifact
	node            collector.Identity
	workID          string
	queued, expires time.Time
	storing         bool
	stop            *collector.ProcessStop
	stopStore       context.CancelFunc
	outcome         evidence.RecordingCollection
}

func (h *ConnectorRecordings) PrepareProcesses(p *objectstore.PreparedArtifact, e artifact.ContextExpectation) *preparedProcesses {
	e.Processes = e.Processes.Clone()
	return &preparedProcesses{holder: h, prepared: p, expectation: e}
}

func (h *ConnectorRecordings) startProcesses(ctx context.Context, p *objectstore.PreparedArtifact, e artifact.ContextExpectation, pin artifact.PinnedPod, started, until time.Time) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil || e.Validate() != nil || !e.Processes.Valid() || pin.UID != e.PodUID || pin.NamespaceUID != e.NamespaceUID || h.pods == nil {
		return time.Time{}, value.ErrInvalid
	}
	if _, err := compiler.ProcessesContextFor(e.Processes); err != nil {
		return time.Time{}, err
	}
	nodes, ok := h.nodes.(processNodes)
	if !ok {
		return time.Time{}, value.ErrUnavailable
	}
	name, err := h.pods.PodNode(ctx, pin)
	if err != nil {
		return time.Time{}, err
	}
	node, ok := nodes.NodeByName(name)
	if !ok || !node.RecorderAvailable(collector.MechanismProcesses) {
		return time.Time{}, value.ErrUnavailable
	}
	deadline := started.Add(time.Duration(e.Processes.TimeoutMillis) * time.Millisecond)
	if deadline.After(e.Registration.WriteUntil) {
		return time.Time{}, value.ErrExpired
	}
	pin.NodeName = name
	work := collector.ProcessCapture{CaptureID: e.CaptureUID, CollectorEpoch: node.Identity.Epoch, ExpectationDigest: evidence.ContextExpectationDigest(e), Request: value.ProcessSnapshotRequest{Pin: pin, NodeUID: node.Identity.NodeUID, NodeBootID: node.Identity.BootID, Mode: e.Processes.Mode, NativeLimit: e.Registration.NativeLimit, NotBefore: started, Deadline: deadline}}
	startBy := deadline
	if until.Before(startBy) {
		startBy = until
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.expireLocked(now)
	if ctx.Err() != nil || !work.Valid() || !now.Before(startBy) || h.heldCountLocked() >= maxHeldRecordings || h.held[e.CaptureUID] != nil || h.profiles[e.CaptureUID] != nil || h.logs[e.CaptureUID] != nil || h.processes[e.CaptureUID] != nil {
		return time.Time{}, value.ErrUnavailable
	}
	w, err := nodes.EnqueueProcesses(ctx, work, startBy)
	if err != nil {
		return time.Time{}, err
	}
	queued := now.UTC().Truncate(time.Microsecond)
	if h.processes == nil {
		h.processes = map[string]*heldProcesses{}
	}
	h.processes[e.CaptureUID] = &heldProcesses{expectation: e, digest: work.ExpectationDigest, prepared: p, node: node.Identity, workID: w.ID, queued: queued, expires: e.Registration.WriteUntil.Add(recordingRetain), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
	return queued, nil
}

func (h *ConnectorRecordings) DeliverProcesses(ctx context.Context, node collector.Identity, r collector.ProcessResult, body io.Reader) error {
	h.mu.Lock()
	h.expireLocked(h.now())
	held := h.processes[r.CaptureID]
	if ctx == nil || body == nil || held == nil || held.node != node || held.workID != r.WorkID || held.digest != r.ExpectationDigest || r.PodUID != held.expectation.PodUID || r.NodeUID != node.NodeUID || r.NodeBootID != node.BootID || held.outcome.State != evidence.RecordingPending || held.prepared == nil || !r.Valid() {
		h.mu.Unlock()
		return value.ErrDenied
	}
	if held.stop != nil {
		held.prepared = nil
		held.outcome = h.processesCancelled(held)
		h.mu.Unlock()
		return nil
	}
	if r.Failure != "" {
		held.prepared = nil
		held.outcome = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "captureFailed"}
		h.mu.Unlock()
		return nil
	}
	held.storing = true
	call, cancel := context.WithDeadline(ctx, held.expectation.Registration.WriteUntil)
	defer cancel()
	held.stopStore = cancel
	p, e := held.prepared, held.expectation
	held.prepared = nil
	if !h.waitStoreLocked(call, e.Registration.WriteUntil, maxStoringBytes) {
		held.storing = false
		held.stopStore = nil
		held.outcome = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "storeUnconfirmed"}
		if held.stop != nil {
			held.outcome = h.processesCancelled(held)
		}
		h.mu.Unlock()
		return value.ErrUnavailable
	}
	h.mu.Unlock()
	defer func() { h.mu.Lock(); h.releaseStoreLocked(maxStoringBytes); held.storing = false; h.mu.Unlock() }()
	// One bounded source buffer binds the native's node/boot to the original
	// authenticated upload. Store repeats the independent accepted native
	// contract check while encrypting; neither traversal reads the source twice.
	raw, err := io.ReadAll(io.LimitReader(body, r.NativeBytes+1))
	var copies artifact.Copies
	if err == nil {
		native, checkErr := processcodec.DecodeProcesses(raw)
		if checkErr != nil || int64(len(raw)) != r.NativeBytes || native.NodeUID != node.NodeUID || native.NodeBootID != node.BootID || native.PodUID != e.PodUID || native.StartedAt.Before(r.StartedAt) || native.CompletedAt.After(r.CompletedAt) {
			err = value.ErrDenied
		}
	}
	if err == nil && call.Err() == nil {
		copies, err = p.Store(call, bytes.NewReader(raw), r.StartedAt, r.CompletedAt)
	}
	clear(raw)
	stored := h.now().UTC().Truncate(time.Microsecond)
	out := evidence.RecordingCollection{State: evidence.RecordingStored, Acquired: held.queued, Completion: artifact.ContextWriterCompletion{RegistrationDigest: privacyapp.RegistrationDigest(e.Registration), ExpectationDigest: held.digest, Copies: copies, StoredAt: stored, ClosedAt: stored}}
	if err != nil || call.Err() != nil || !out.Valid(e.Registration) {
		out = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "storeUnconfirmed"}
	}
	h.mu.Lock()
	if out.State != evidence.RecordingStored && held.stop != nil {
		out = h.processesCancelled(held)
	}
	held.outcome = out
	h.mu.Unlock()
	if out.State != evidence.RecordingStored {
		return value.ErrUnavailable
	}
	return nil
}

func (h *ConnectorRecordings) collectProcesses(w fleet.APIContextWork) (evidence.RecordingCollection, bool, error) {
	p := h.processes[w.CaptureID]
	if p == nil {
		return evidence.RecordingCollection{}, false, nil
	}
	attempt := p.expectation.Registration.Location.AttemptID
	if p.stop != nil {
		attempt = p.stop.AttemptID
	}
	if attempt != w.AttemptID || p.digest != w.ExpectationDigest {
		return evidence.RecordingCollection{}, true, value.ErrDenied
	}
	return p.outcome, true, nil
}

type preparedProcesses struct {
	holder      *ConnectorRecordings
	expectation artifact.ContextExpectation
	mu          sync.Mutex
	prepared    *objectstore.PreparedArtifact
}

var _ evidence.ProcessesRecorder = (*preparedProcesses)(nil)

func (p *preparedProcesses) Close() { p.mu.Lock(); p.prepared = nil; p.mu.Unlock() }
func (p *preparedProcesses) StoreContext(context.Context, []byte, time.Time, time.Time) (artifact.Copies, error) {
	return artifact.Copies{}, value.ErrUnavailable
}
func (p *preparedProcesses) StartProcesses(ctx context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, error) {
	p.mu.Lock()
	prepared := p.prepared
	p.prepared = nil
	p.mu.Unlock()
	if prepared == nil {
		return time.Time{}, value.ErrDenied
	}
	return p.holder.startProcesses(ctx, prepared, p.expectation, pin, started, until)
}
