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
	outcome         evidence.RecordingCollection
}

// Profiles share the connector's existing64 holders and32MiB storage working
// budget. One streaming profile reserves that whole working budget regardless
// of its admitted total bytes; data is encrypted in bounded8MiB frames.
func (h *ConnectorRecordings) PrepareProfile(p *objectstore.PreparedArtifact, e artifact.ContextExpectation) *preparedProfile {
	if e.Profile != nil {
		profile := *e.Profile
		profile.Composition = append([]byte(nil), profile.Composition...)
		e.Profile = &profile
	}
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
	if !ok {
		return time.Time{}, value.ErrUnavailable
	}
	node, ok := nodes.NodeByName(plan.Pin.NodeName)
	if !ok || !node.RecorderAvailable(collector.MechanismProfile) || node.Identity.NodeUID != plan.NodeUID || node.Identity.BootID != plan.NodeBootID {
		return time.Time{}, value.ErrUnavailable
	}
	deadline := started.Add(time.Duration(e.Profile.TimeoutMillis) * time.Millisecond)
	if deadline.After(e.Registration.WriteUntil) {
		return time.Time{}, value.ErrExpired
	}
	request := value.GoProfileRequest{Binding: e.Binding(), Pin: plan.Pin, NodeUID: plan.NodeUID, NodeBootID: plan.NodeBootID, SourceRef: plan.SourceRef, EndpointDigest: plan.EndpointDigest, Parameters: plan.Parameters, NativeLimit: plan.NativeLimit, NotBefore: started, Deadline: deadline}
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
	if h.storing != 0 {
		held.prepared = nil
		held.outcome = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "storeUnconfirmed"}
		h.mu.Unlock()
		return value.ErrUnavailable
	}
	h.storing += maxStoringBytes
	held.storing = true
	p, e := held.prepared, held.expectation
	held.prepared = nil
	h.mu.Unlock()
	defer func() { h.mu.Lock(); h.storing -= maxStoringBytes; held.storing = false; h.mu.Unlock() }()
	copies, err := p.Store(ctx, body, r.Outcome.StartedAt.UTC(), r.Outcome.CompletedAt.UTC())
	stored := h.now().UTC().Truncate(time.Microsecond)
	out := evidence.RecordingCollection{State: evidence.RecordingStored, Acquired: held.queued, Completion: artifact.ContextWriterCompletion{RegistrationDigest: privacyapp.RegistrationDigest(e.Registration), ExpectationDigest: held.digest, Copies: copies, StoredAt: stored, ClosedAt: stored}}
	if err != nil || !out.Valid(e.Registration) {
		out = evidence.RecordingCollection{State: evidence.RecordingFailed, Acquired: held.queued, Failure: "storeUnconfirmed"}
	}
	h.mu.Lock()
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
	if p.expectation.Registration.Location.AttemptID != w.AttemptID || p.digest != w.ExpectationDigest {
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
