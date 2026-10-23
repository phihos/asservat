package evidence

import (
	"context"
	"errors"
	"sync"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type ProjectionCredential struct {
	Enrollment value.AcquisitionEnrollment
	Peer       value.KeyPeer
	Ready      bool
}
type ProjectionIdentityLedger interface {
	ReadProjectionCredential(context.Context, query.ContextQuery, query.ContextQueryRequest, query.ContextProjectionAuthority) (ProjectionCredential, error)
	BindProjectionIdentity(context.Context, query.ContextQuery, query.ContextQueryRequest, query.ContextProjectionAuthority, ProjectionCredential) (query.ContextQueryWorker, error)
}
type ProjectionNativeControl interface {
	ClaimProjectionNative(context.Context, query.ContextReadStart, query.ContextProjectionAuthority, value.NativeOperation) error
	ObserveProjectionNativeOperation(context.Context, value.NativeReference, value.KeyPeer) (value.NativeLease, error)
	CompleteProjectionNative(context.Context, value.NativeLease) error
	BindProjectionNativeKeys(context.Context, query.ContextReadStart, query.ContextProjectionAuthority, value.NativeOperation, value.KeyScope, NativeOrigin) error
}
type ProjectionSources interface {
	ReadProjectionSource(context.Context, query.ContextQuery, query.ContextProjectionAuthority, query.ContextQueryRequest) (NativeContextSource, error)
}
type ProjectionRuntime struct {
	Workers                    ProjectionWorkerLedger
	Identities                 ProjectionIdentityLedger
	Jobs                       AcquisitionWorkerJobs
	Sources                    ProjectionSources
	Operations                 ProjectionNativeControl
	Origins                    NativeOrigins
	Registrar                  NativeExchangeRegistrar
	KeyScope                   value.KeyScope
	HubPodUID, HubProcessEpoch string
	Now                        func() time.Time
	Cleanup                    *ProjectionWorkerCleanup
}

// Observe is limited to the previously admitted exact Job. No failure triggers
// create/replacement, a new worker or an enrollment reset. Enrollment proceeds
// independently in that worker, under its original finite lifetime (ADR-221).
func (s *ProjectionRuntime) ObserveProjectionWorker(ctx context.Context, q query.ContextQuery, owner ContextProjectionRequestOwner) (ProjectionWorkerObservation, error) {
	var zero ProjectionWorkerObservation
	if s == nil || ctx == nil || owner == nil || s.Workers == nil || s.Identities == nil || s.Jobs == nil || s.Now == nil {
		return zero, query.ErrUnavailable
	}
	if s.Cleanup != nil {
		s.Cleanup.CleanupProjectionWorkers(ctx)
	}
	a, e := owner.CheckCurrent(ctx)
	if e != nil || !q.Current(a, s.Now()) {
		return zero, query.ErrUnavailable
	}
	r := owner.Request()
	call, stop := context.WithDeadline(ctx, identity.Earlier(a.ValidUntil, r.Call.Until))
	defer stop()
	current := func() bool { return call.Err() == nil && q.Current(a, s.Now()) && r.Valid(s.Now()) }
	state, e := s.Workers.ReadProjectionWorker(call, q, r, a)
	if e != nil || !state.Intent.Valid() || !state.Intent.Query.Equal(q) || !state.Audited || !state.Claimed || !current() {
		return zero, query.ErrUnavailable
	}
	// Unknown create can only be resolved by exact lookup of the deterministic
	// existing Job. Recording the observation is not another launch permission.
	if !state.Job.ValidAcquisition(state.Intent.Worker) {
		state.Job, e = s.Jobs.FindAcquisitionWorkerJob(call, state.Intent.Worker)
		if e != nil || !current() {
			return zero, query.ErrUnavailable
		}
		if e = s.Workers.RecordProjectionWorkerJob(call, state.Intent, state.Job, r, a); e != nil {
			return zero, e
		}
	}
	observed, e := s.Jobs.ObserveAcquisitionWorker(call, state.Intent.Worker, state.Job)
	if e != nil {
		var pending *AcquisitionWorkerPending
		if errors.As(e, &pending) && pending.Valid(s.Now()) && pending.Intent == state.Intent.Worker && current() {
			return ProjectionWorkerObservation{ObservedAt: s.Now(), ValidUntil: identity.Earlier(a.ValidUntil, r.Call.Until)}, nil
		}
		return zero, e
	}
	if !observed.Valid() || observed.Intent != state.Intent.Worker || observed.Job != state.Job || state.Worker.Valid() && state.Worker != observed || !current() {
		return zero, query.ErrUnavailable
	}
	if e = s.Workers.BindProjectionWorker(call, state.Intent, observed, r, a); e != nil {
		return zero, e
	}
	credential, e := s.Identities.ReadProjectionCredential(call, q, r, a)
	if e != nil || !current() {
		return zero, query.ErrUnavailable
	}
	if !credential.Ready {
		return ProjectionWorkerObservation{ObservedAt: s.Now(), ValidUntil: identity.Earlier(a.ValidUntil, r.Call.Until)}, nil
	}
	w, e := s.Identities.BindProjectionIdentity(call, q, r, a, credential)
	if e != nil || !current() {
		return zero, query.ErrUnavailable
	}
	return ProjectionWorkerObservation{Worker: w, Ready: true, ObservedAt: s.Now(), ValidUntil: identity.Earlier(a.ValidUntil, identity.Earlier(r.Call.Until, credential.Peer.NotAfter))}, nil
}

// The shape is structurally shared with C-18 without importing its application
// package into C-14. The bootstrap adapter performs the trivial value mapping.
type ProjectionWorkerObservation struct {
	Worker                 query.ContextQueryWorker
	Ready                  bool
	ObservedAt, ValidUntil time.Time
}

// This remote handle retains the real native operation, its positive protocol
// close and the independently current public request. No DTO exposes Joined.
type projectionRead struct {
	cancel           context.CancelFunc
	runtime          *ProjectionRuntime
	query            query.ContextQuery
	start            query.ContextReadStart
	owner            ContextProjectionRequestOwner
	operation        value.NativeOperation
	pending          NativePendingExchange
	exchange         NativeProjectionExchange
	mu               sync.Mutex
	closed, positive bool
	once             sync.Once
	closeErr         error
}

func (s *ProjectionRuntime) ReadProjection(ctx context.Context, q query.ContextQuery, start query.ContextReadStart, owner ContextProjectionRequestOwner) (*projectionRead, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || owner == nil || s.Now == nil || s.Sources == nil || s.Identities == nil || s.Operations == nil || s.Registrar == nil || s.Origins.Projection == nil || !s.KeyScope.Valid() || !value.UUID(s.HubPodUID) || !value.UUID(s.HubProcessEpoch) || !start.Fresh || start.ClaimID != start.Batch.ID || !start.Batch.Matches(q) || start.Batch.Request != owner.Request() {
		return nil, query.ErrUnavailable
	}
	a, e := owner.CheckCurrent(ctx)
	if e != nil || !start.Batch.Current(q, a, s.Now()) {
		return nil, query.ErrUnavailable
	}
	until := identity.Earlier(start.Batch.Until, identity.Earlier(a.ValidUntil, q.ProviderUntil))
	call, stop := context.WithDeadline(ctx, until)
	fail := true
	defer func() {
		if fail {
			stop()
		}
	}()
	c, e := s.Identities.ReadProjectionCredential(call, q, owner.Request(), a)
	if e != nil || !c.Ready || !c.Enrollment.Valid() || c.Enrollment.Worker.Intent.ID != q.WorkerID || c.Peer.Certificate != start.Batch.Worker.Certificate || c.Peer.PeerID != start.Batch.Worker.PeerID {
		return nil, query.ErrUnavailable
	}
	source, e := s.Sources.ReadProjectionSource(call, q, a, owner.Request())
	if e != nil || !ProjectionSourceMatches(source, q, a) {
		return nil, query.ErrUnavailable
	}
	now := s.Now().UTC().Truncate(time.Microsecond)
	until = identity.Earlier(until, identity.Earlier(c.Peer.NotAfter, now.Add(identity.EvidenceReadRequestWindow))).UTC().Truncate(time.Microsecond)
	operation := value.NativeOperation{Kind: value.NativeProjection, Path: a.Environment.Path.AcquisitionPath(), Processing: a.Environment.Processing,
		Reference: value.NativeReference{InstallationID: q.Plan.InstallationID, QueryID: q.ID, WorkerID: q.WorkerID, OperationID: start.Batch.ID, Fence: start.Batch.Generation},
		HubPodUID: s.HubPodUID, HubProcessEpoch: s.HubProcessEpoch, WorkerPodUID: c.Enrollment.Worker.Binding.PodUID, WorkerPublicKey: c.Enrollment.PublicKeyDigest,
		SourceVersion: q.Scope.Version, ParentID: start.Batch.ID, Generation: start.Batch.Generation, StartedAt: now, Until: until}
	if !operation.CurrentValid(s.Now()) || !start.Batch.Current(q, a, s.Now()) || call.Err() != nil {
		return nil, query.ErrUnavailable
	}
	h := &projectionRead{runtime: s, query: q, start: start, owner: owner, operation: operation, cancel: stop}
	current := func(bound context.Context, origin NativeOrigin) (value.NativeLease, error) {
		var zero value.NativeLease
		fresh, e := owner.CheckCurrent(bound)
		if e != nil || call.Err() != nil {
			return zero, collapsed("request", query.ErrUnavailable, errors.Join(e, call.Err()))
		}
		if !start.Batch.Current(q, fresh, s.Now()) {
			return zero, stepped("batch", query.ErrUnavailable)
		}
		if fresh.Scope != a.Scope || fresh.Environment.Path != a.Environment.Path || !fresh.Environment.Processing.Equal(a.Environment.Processing) || origin.Proof.Binding != c.Enrollment.Worker.Binding || origin.Proof.Peer.Certificate != start.Batch.Worker.Certificate {
			return zero, stepped("binding", query.ErrUnavailable)
		}
		lease, e := s.Origins.Recheck(bound, origin)
		if e != nil {
			return zero, collapsed("origin", query.ErrUnavailable, e)
		}
		if !lease.Operation.Equal(operation) {
			return zero, stepped("operation", query.ErrUnavailable)
		}
		lease.Until = identity.Earlier(lease.Until, identity.Earlier(until, fresh.ValidUntil))
		if !lease.Valid(s.Now()) || call.Err() != nil {
			return zero, stepped("lease", query.ErrUnavailable)
		}
		return lease, nil
	}
	before := func(bound context.Context, origin NativeOrigin) error {
		lease, e := current(bound, origin)
		if e != nil {
			return e
		}
		effect, end := context.WithDeadline(bound, lease.Until)
		defer end()
		return s.Operations.BindProjectionNativeKeys(effect, start, a, operation, s.KeyScope, origin)
	}
	complete := func(bound context.Context, lease value.NativeLease) error {
		if !lease.Operation.Equal(operation) || lease.Certificate != start.Batch.Worker.Certificate {
			return query.ErrUnavailable
		}
		return s.Operations.CompleteProjectionNative(bound, lease)
	}
	pending, e := s.Registrar.RegisterNativeExchange(call, NativeExchangeRegistration{Operation: operation, Projection: &q.Scope, Source: source, Complete: complete}, before, current)
	if e != nil {
		return nil, e
	}
	h.pending = pending
	// Registration precedes publication. Once publication is uncertain, no
	// replacement/second claim is attempted; closing retains all spent state.
	if e = s.Operations.ClaimProjectionNative(call, start, a, operation); e != nil {
		pending.Close()
		return nil, e
	}
	exchange, e := pending.Wait(call)
	if e != nil {
		pending.Close()
		return nil, e
	}
	approved, ok := exchange.(NativeProjectionExchange)
	if !ok {
		pending.Close()
		return nil, query.ErrUnavailable
	}
	h.exchange = approved
	fail = false
	return h, nil
}
func (h *projectionRead) Projection(ctx context.Context) (query.PodStatusProjection, error) {
	var zero query.PodStatusProjection
	if h == nil || h.exchange == nil || ctx == nil || ctx.Err() != nil {
		return zero, query.ErrUnavailable
	}
	h.mu.Lock()
	allowed := !h.closed && !h.positive
	h.mu.Unlock()
	if !allowed {
		return zero, query.ErrUnavailable
	}
	p, e := h.exchange.Projection(ctx)
	if e != nil {
		return zero, e
	}
	if e = h.exchange.AcknowledgeProjection(ctx); e != nil {
		return zero, e
	}
	a, e := h.owner.CheckCurrent(ctx)
	if e != nil || !h.start.Batch.Current(h.query, a, h.runtime.Now()) || ctx.Err() != nil {
		return zero, query.ErrUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return zero, query.ErrUnavailable
	}
	h.positive = true
	return p, nil
}
func (h *projectionRead) CheckCurrent(ctx context.Context) error {
	if h == nil || ctx == nil || ctx.Err() != nil {
		return query.ErrUnavailable
	}
	h.mu.Lock()
	ready := h.positive && !h.closed
	h.mu.Unlock()
	if !ready {
		return query.ErrUnavailable
	}
	a, e := h.owner.CheckCurrent(ctx)
	if e != nil || !h.start.Batch.Current(h.query, a, h.runtime.Now()) {
		return query.ErrUnavailable
	}
	return nil
}
func (h *projectionRead) Close(ctx context.Context) error {
	if h == nil {
		return query.ErrUnavailable
	}
	h.once.Do(func() {
		h.cancel()
		h.pending.Close()
		h.mu.Lock()
		defer h.mu.Unlock()
		h.closed = true
		if !h.positive || ctx == nil || ctx.Err() != nil || !h.runtime.Now().Before(h.start.Batch.CleanupUntil) {
			h.closeErr = query.ErrUnavailable
		}
	})
	return h.closeErr
}
func (h *projectionRead) WithProjectionClosed(ctx context.Context, b query.ContextReadBatch, fn func(context.Context) error) error {
	if h == nil || ctx == nil || ctx.Err() != nil || fn == nil || !b.Equal(h.start.Batch) {
		return query.ErrUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed || !h.positive || h.closeErr != nil || !h.runtime.Now().Before(b.CleanupUntil) {
		return query.ErrUnavailable
	}
	call, stop := context.WithDeadline(ctx, b.CleanupUntil)
	defer stop()
	if e := fn(call); e != nil {
		return e
	}
	if call.Err() != nil || !h.runtime.Now().Before(b.CleanupUntil) {
		return query.ErrUnavailable
	}
	return nil
}
