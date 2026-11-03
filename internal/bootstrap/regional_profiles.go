package bootstrap

import (
	"context"
	"io"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
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

type profileEndpointPlans interface {
	ResolveProfilePlan(context.Context, targets.ProfileEndpointRequest) (planning.GoEndpointPlan, error)
}
type profileNodes interface {
	NodeByName(string) (delivery.NodeView, bool)
	EnqueueProfile(context.Context, collector.ProfileCapture, time.Time) (collector.Work, error)
}
type heldProfile struct {
	expectation     artifact.ContextExpectation
	digest          artifact.Digest
	prepared        *objectstore.PreparedArtifact
	node            collector.Identity
	workID          string
	queued, expires time.Time
	storing         bool
	stop            *collector.ProfileStop
	stopStore       context.CancelFunc
	mayHaveStarted  bool
	outcome         evidence.RecordingCollection
}

// Profiles share the connector's existing64 holders and32MiB storage working
// budget. One streaming profile reserves that whole working budget regardless
// of its admitted total bytes; data is encrypted in bounded8MiB frames.
func (h *ConnectorRecordings) PrepareProfile(p *objectstore.PreparedArtifact, e artifact.ContextExpectation) *preparedProfile {
	e.Profile = e.Profile.Clone()
	return &preparedProfile{holder: h, prepared: p, expectation: e}
}
func (h *ConnectorRecordings) startProfile(ctx context.Context, p *objectstore.PreparedArtifact, e artifact.ContextExpectation, pin artifact.PinnedPod, started, until time.Time, endpoint targets.ProfileEndpointRequest) (time.Time, error) {
	frozen, err := compiler.ProfileContextFor(e.Profile)
	if err != nil || ctx == nil || ctx.Err() != nil || h.profileEndpoints == nil || pin.UID != e.PodUID || pin.NamespaceUID != e.NamespaceUID || !endpoint.Equal(frozen.Endpoints[0].Request) {
		return time.Time{}, value.ErrInvalid
	}
	plan, err := h.profileEndpoints.ResolveProfilePlan(ctx, endpoint)
	if err != nil {
		return time.Time{}, err
	}
	now := h.now()
	if !now.Before(plan.ValidUntil) || plan.EndpointDigest != e.Profile.EndpointDigest || plan.DefinitionDigest != frozen.Endpoints[0].DefinitionDigest || plan.Definition.TLS != nil || plan.Definition.Credential != nil || plan.Pin.UID != pin.UID || plan.Pin.NamespaceUID != pin.NamespaceUID {
		return time.Time{}, value.ErrDenied
	}
	nodes, ok := h.nodes.(profileNodes)
	if !ok || h.pods == nil {
		return time.Time{}, value.ErrUnavailable
	}
	// API-class endpoint plans intentionally retain a node-free accepted pin.
	// Reuse packet dispatch's exact Pod lookup, then bind the private mechanism
	// to the current attested collector. Never invent a node identity or change
	// the accepted pin/endpoint digest to make that dispatch possible.
	name, err := h.pods.PodNode(ctx, pin)
	if err != nil {
		return time.Time{}, value.ErrUnavailable
	}
	node, ok := nodes.NodeByName(name)
	if !ok || !node.RecorderAvailable(collector.MechanismProfile) ||
		(plan.Pin.NodeName != "" && plan.Pin.NodeName != name) ||
		(plan.NodeUID != "" && node.Identity.NodeUID != plan.NodeUID) ||
		(plan.NodeBootID != "" && node.Identity.BootID != plan.NodeBootID) {
		return time.Time{}, value.ErrUnavailable
	}
	deadline := started.Add(time.Duration(e.Profile.TimeoutMillis) * time.Millisecond)
	if deadline.After(e.Registration.WriteUntil) {
		return time.Time{}, value.ErrExpired
	}
	mechanismPin := plan.Pin
	mechanismPin.NodeName = name
	request := value.GoProfileRequest{Binding: e.Binding(), Pin: mechanismPin, NodeUID: node.Identity.NodeUID, NodeBootID: node.Identity.BootID, SourceRef: plan.SourceRef, EndpointDigest: plan.EndpointDigest, Parameters: plan.Parameters, NativeLimit: plan.NativeLimit, NotBefore: started, Deadline: deadline}
	work := collector.ProfileCapture{CaptureID: e.CaptureUID, ExpectationDigest: evidence.ContextExpectationDigest(e), DefinitionDigest: plan.DefinitionDigest, CollectorEpoch: node.Identity.Epoch, Request: request, AddressMode: plan.AddressMode, Address: plan.RouteIP, Port: plan.Port, Host: plan.Definition.Host}
	startBy := deadline.Add(-request.Parameters.Duration - 2*time.Second)
	if until.Before(startBy) {
		startBy = until
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now = h.now()
	h.expireLocked(now)
	if ctx.Err() != nil || !now.Before(startBy) || !now.Before(plan.ValidUntil) || !work.Valid() || len(h.held)+len(h.profiles) >= maxHeldRecordings || h.held[e.CaptureUID] != nil || h.profiles[e.CaptureUID] != nil {
		return time.Time{}, value.ErrUnavailable
	}
	w, err := nodes.EnqueueProfile(ctx, work, startBy)
	if err != nil {
		return time.Time{}, err
	}
	queued := now.UTC().Truncate(time.Microsecond)
	if h.profiles == nil {
		h.profiles = map[string]*heldProfile{}
	}
	h.profiles[e.CaptureUID] = &heldProfile{expectation: e, digest: work.ExpectationDigest, prepared: p, node: node.Identity, workID: w.ID, queued: queued, expires: e.Registration.WriteUntil.Add(recordingRetain), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
	return queued, nil
}

func (h *ConnectorRecordings) DeliverProfile(ctx context.Context, node collector.Identity, r collector.ProfileResult, body io.Reader) error {
	h.mu.Lock()
	h.expireLocked(h.now())
	held := h.profiles[r.CaptureID]
	if held == nil || held.node != node || held.workID != r.WorkID || held.digest != r.ExpectationDigest || held.expectation.Profile.EndpointDigest != r.EndpointDigest || held.outcome.State != evidence.RecordingPending || held.prepared == nil || !r.Valid() {
		h.mu.Unlock()
		return value.ErrDenied
	}
	held.mayHaveStarted = r.Outcome.MayHaveStarted
	if held.stop != nil {
		held.prepared = nil
		held.outcome = h.profileCancelled(held, r.Outcome.MayHaveStarted)
		h.mu.Unlock()
		return nil
	}
	if r.Failure != "" {
		failure := "captureFailed"
		if r.Failure == collector.ReasonCaptureBusy {
			failure = evidence.RecordingProfilerBusy
		}
		held.prepared = nil
		held.outcome = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: failure}
		h.mu.Unlock()
		return nil
	}
	// Claim the single delivery before releasing the lock, including its wait
	// for the shared working budget. The completed body stays unread, and Stop
	// cancels this same original-deadline context while waiting or storing.
	held.storing = true
	storeCtx, cancelStore := context.WithDeadline(ctx, held.expectation.Registration.WriteUntil)
	defer cancelStore()
	held.stopStore = cancelStore
	p, e := held.prepared, held.expectation
	held.prepared = nil
	// Capacity becoming available cannot renew an expired/cancelled attempt.
	if !h.waitStoreLocked(storeCtx, e.Registration.WriteUntil, maxStoringBytes) {
		held.stopStore = nil
		held.storing = false
		held.outcome = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "storeUnconfirmed"}
		if held.stop != nil {
			held.outcome = h.profileCancelled(held, held.mayHaveStarted)
		}
		h.mu.Unlock()
		return value.ErrUnavailable
	}
	h.mu.Unlock()
	defer func() { h.mu.Lock(); h.releaseStoreLocked(maxStoringBytes); held.storing = false; h.mu.Unlock() }()
	copies, err := p.Store(storeCtx, body, r.Outcome.StartedAt.UTC(), r.Outcome.CompletedAt.UTC())
	stored := h.now().UTC().Truncate(time.Microsecond)
	out := evidence.RecordingCollection{State: evidence.RecordingStored, Acquired: held.queued, Completion: artifact.ContextWriterCompletion{RegistrationDigest: privacyapp.RegistrationDigest(e.Registration), ExpectationDigest: held.digest, Copies: copies, StoredAt: stored, ClosedAt: stored}}
	if err != nil || !out.Valid(e.Registration) {
		out = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "storeUnconfirmed"}
	}
	h.mu.Lock()
	held.stopStore = nil
	if held.stop != nil && out.State != evidence.RecordingStored {
		out = h.profileCancelled(held, true)
	}
	held.outcome = out
	h.mu.Unlock()
	if err != nil {
		return value.ErrUnavailable
	}
	return nil
}

func (h *ConnectorRecordings) collectProfile(w fleet.APIContextWork) (evidence.RecordingCollection, bool, error) {
	p := h.profiles[w.CaptureID]
	if p == nil {
		return evidence.RecordingCollection{}, false, nil
	}
	attemptID := p.expectation.Registration.Location.AttemptID
	if p.stop != nil {
		attemptID = p.stop.AttemptID
	}
	if attemptID != w.AttemptID || p.digest != w.ExpectationDigest {
		return evidence.RecordingCollection{}, true, value.ErrDenied
	}
	return p.outcome, true, nil
}

type preparedProfile struct {
	holder      *ConnectorRecordings
	expectation artifact.ContextExpectation
	mu          sync.Mutex
	prepared    *objectstore.PreparedArtifact
}

var _ evidence.ProfileRecorder = (*preparedProfile)(nil)

func (p *preparedProfile) StoreContext(context.Context, []byte, time.Time, time.Time) (artifact.Copies, error) {
	return artifact.Copies{}, value.ErrUnavailable
}
func (p *preparedProfile) Close() { p.mu.Lock(); p.prepared = nil; p.mu.Unlock() }
func (p *preparedProfile) StartProfile(ctx context.Context, pin artifact.PinnedPod, started, until time.Time, endpoint targets.ProfileEndpointRequest) (time.Time, error) {
	p.mu.Lock()
	prepared := p.prepared
	p.prepared = nil
	p.mu.Unlock()
	if prepared == nil {
		return time.Time{}, value.ErrDenied
	}
	return p.holder.startProfile(ctx, prepared, p.expectation, pin, started, until, endpoint)
}
