package evidence

import (
	"context"
	"sync"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// This port is structural so C-14 never imports C-18. Its production owner is
// the actual original private request, not an implementation decoded from JSON.
type ContextProjectionRequestOwner interface {
	Request() value.ContextQueryRequest
	CheckCurrent(context.Context) (value.ContextProjectionAuthority, error)
}

// Open independently verifies the SQL-spent one-use start, acknowledged audit,
// accepted backing, actual peer/process/Pod proof and current live owner. A
// certificate, Fresh bit or caller-built proof cannot implement that authority.
// The returned process handle retains those current checks and original bounds.
type ContextProjectionExecutionGuard interface {
	OpenProjectionExecution(context.Context, value.ContextQuery, value.ContextReadStart, ContextProjectionRequestOwner) (ContextProjectionExecution, error)
}
type ContextProjectionExecution interface {
	WorkerProof() value.ContextProjectionWorkerProof
	CheckCurrent(context.Context) (value.ContextProjectionAuthority, error)
	CloseExecution(context.Context) error
}
type ContextProjectionSources interface {
	ReadProjectionSource(context.Context, value.ContextQuery, value.ContextProjectionAuthority) (NativeContextSource, error)
}

// This regional adapter performs full authenticated source verification before
// returning the fixed DTO. Native bytes and the scoped opener stay in A-ACQUIRE.
type ContextProjectionNativeRead interface {
	ReadProjectionNative(context.Context, NativeContextSource, value.ContextProjectionScope, KeyOpener, time.Time) (value.PodStatusProjection, error)
}

// ContextProjectionKeyOperations is a query-only private key effect boundary.
// Its implementation must independently consume the exact durable role once
// under current start/worker/live-owner/recovery/retention fences, including the
// whole request hash and sealed key. It may not delegate to download authority
// or turn this DTO into a grant. Missing protected implementation denies runtime.
type ContextProjectionKeyOperations interface {
	OpenProjectionKey(context.Context, value.ContextProjectionKeyBinding, value.ContextProjectionKeyRole, artifact.SealedKey, []byte) ([]byte, error)
}

// RegionalContextProjection is one actual admitted regional worker process for
// one immutable query. Its startup pins and ports require protected composition.
// It is not a hub reader: it exposes only local execution/join, never C-18's
// remote WithProjectionClosed capability or an unwrapping port to the hub.
type RegionalContextProjection struct {
	ctx      context.Context
	cancel   context.CancelFunc
	query    value.ContextQuery
	worker   value.ContextQueryWorker
	guard    ContextProjectionExecutionGuard
	sources  ContextProjectionSources
	native   ContextProjectionNativeRead
	keys     ContextProjectionKeyOperations
	keyScope authorization.KeyScope
	now      func() time.Time
	mu       sync.Mutex
	active   bool
	spent    [value.ContextMaxReadBatches]bool
}

func NewRegionalContextProjection(ctx context.Context, q value.ContextQuery, w value.ContextQueryWorker, guard ContextProjectionExecutionGuard, sources ContextProjectionSources, native ContextProjectionNativeRead, keys ContextProjectionKeyOperations, keyScope authorization.KeyScope, now func() time.Time) (*RegionalContextProjection, error) {
	if ctx == nil || ctx.Err() != nil || now == nil || !q.Valid() || !w.Matches(q) || !now().Before(q.WorkerUntil) || guard == nil || sources == nil || native == nil || keys == nil ||
		!keyScope.Valid() || keyScope.Purpose != "artifact" || keyScope.InstallationID != q.Plan.InstallationID {
		return nil, value.ErrUnavailable
	}
	work, cancel := context.WithDeadline(ctx, q.WorkerUntil)
	return &RegionalContextProjection{ctx: work, cancel: cancel, query: q, worker: w, guard: guard, sources: sources, native: native, keys: keys, keyScope: keyScope, now: now}, nil
}

// StopLocal revokes local work only. It proves no remote process/provider join
// or physical retirement and never changes SQL accounting.
func (w *RegionalContextProjection) StopLocal() {
	if w != nil {
		w.cancel()
	}
}

func ProjectionSourceMatches(s NativeContextSource, q value.ContextQuery, a value.ContextProjectionAuthority) bool {
	e := s.Expectation
	return s.Valid(q.Scope.Version) && e.Registration.NativeLimit == artifact.MaxContextBytes && e.ActionID == "pod-status" && e.DataClass == "metadata" &&
		e.CaseID == q.Scope.CaseID && e.CaptureUID == q.Scope.CaptureID && e.NamespaceUID == q.Scope.NamespaceUID && e.WorkloadUID == q.Scope.WorkloadUID && e.PodUID == q.Scope.PodUID &&
		e.Registration.Location == a.Environment.Location && e.Registration.StoreID == a.Environment.StoreID &&
		!a.AccessUntil.After(e.Registration.ExpiresAt) && !a.DeleteBy.After(e.Registration.DeleteBy)
}

// RegionalProjectionRead deliberately does NOT implement Close or
// WithProjectionClosed. Its local join cannot be passed to C-18/SQL as proof
// that an independently authenticated remote operation and transport joined.
type RegionalProjectionRead struct {
	worker                   *RegionalContextProjection
	start                    value.ContextReadStart
	owner                    ContextProjectionRequestOwner
	execution                ContextProjectionExecution
	proof                    value.ContextProjectionWorkerProof
	ctx                      context.Context
	cancel                   context.CancelFunc
	done                     chan struct{}
	mu                       sync.Mutex
	until                    time.Time
	timer                    *time.Timer
	projection               value.PodStatusProjection
	ready, closed, uncertain bool
	checking                 chan struct{}
	once                     sync.Once
	closeErr                 error
}

type projectionReadContext struct {
	context.Context
	read *RegionalProjectionRead
}

func (c projectionReadContext) Deadline() (time.Time, bool) {
	parent, hasParent := c.Context.Deadline()
	c.read.mu.Lock()
	defer c.read.mu.Unlock()
	until := c.read.until
	if hasParent {
		until = identity.Earlier(until, parent)
	}
	return until, true
}

func (w *RegionalContextProjection) ExecuteProjection(ctx context.Context, start value.ContextReadStart, owner ContextProjectionRequestOwner) (*RegionalProjectionRead, error) {
	if w == nil || ctx == nil || ctx.Err() != nil || w.ctx.Err() != nil || owner == nil || !start.Fresh || start.ClaimID != start.Batch.ID ||
		!start.Batch.Matches(w.query) || start.Batch.Worker != w.worker || owner.Request() != start.Batch.Request {
		return nil, value.ErrUnavailable
	}
	until := identity.Earlier(w.query.ProviderUntil, identity.Earlier(start.Batch.Until, identity.Earlier(w.query.Deadline, w.now().Add(5*time.Second))))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	if !w.now().Before(until) {
		return nil, value.ErrExpired
	}
	index := start.Batch.Generation - 1
	w.mu.Lock()
	if w.active || w.spent[index] || w.ctx.Err() != nil {
		w.mu.Unlock()
		return nil, value.ErrUnavailable
	}
	w.active = true
	w.spent[index] = true
	w.mu.Unlock()
	owned, cancel := context.WithDeadline(ctx, until)
	stopWorker := context.AfterFunc(w.ctx, cancel)
	r := &RegionalProjectionRead{worker: w, start: start, owner: owner, until: until, done: make(chan struct{})}
	r.ctx = projectionReadContext{Context: owned, read: r}
	r.cancel = func() {
		cancel()
		stopWorker()
		r.mu.Lock()
		if r.timer != nil {
			r.timer.Stop()
		}
		r.projection = value.PodStatusProjection{}
		r.mu.Unlock()
	}
	defer close(r.done)
	// Cancellation drops retained DTO references; joining is an explicit local
	// obligation and remains distinct from the future remote protocol's proof.
	stopClear := context.AfterFunc(owned, func() { r.mu.Lock(); r.projection = value.PodStatusProjection{}; r.mu.Unlock() })
	defer func() {
		if r.ctx.Err() != nil {
			stopClear()
		}
	}()
	execution, err := w.guard.OpenProjectionExecution(r.ctx, w.query, start, owner)
	r.execution = execution
	if err != nil || execution == nil {
		r.uncertain = true
		r.cancel()
		return r, value.ErrUnavailable
	}
	r.proof = execution.WorkerProof()
	if !r.proof.Matches(w.query, w.worker, w.now()) || !r.shorten(r.proof.ValidUntil) {
		r.cancel()
		return r, value.ErrUnavailable
	}
	a, err := r.check(r.ctx)
	if err != nil {
		r.cancel()
		return r, err
	}
	source, err := w.sources.ReadProjectionSource(r.ctx, w.query, a)
	source = cloneNativeSource(source)
	if err != nil || !ProjectionSourceMatches(source, w.query, a) {
		r.cancel()
		return r, value.ErrUnavailable
	}
	a, err = r.check(r.ctx)
	if err != nil || !ProjectionSourceMatches(source, w.query, a) {
		r.cancel()
		return r, value.ErrUnavailable
	}
	r.mu.Lock()
	keyUntil := r.until
	r.mu.Unlock()
	binding := value.ContextProjectionKeyBinding{Purpose: value.ContextProjectionPurpose, ClaimID: start.ClaimID, Batch: start.Batch, SourceVersion: w.query.Scope.Version,
		Scope: w.keyScope, Worker: r.proof, Authority: a, CreatedAt: w.now(), Until: keyUntil}
	if !binding.Valid(w.query, w.now()) {
		r.cancel()
		return r, value.ErrUnavailable
	}
	opener := &projectionKeyOpener{read: r, binding: binding, artifact: source.Expectation.Binding()}
	projection, err := w.native.ReadProjectionNative(r.ctx, source, w.query.Scope, opener, keyUntil)
	if err != nil || !projection.Valid() || projection.NamespaceUID != w.query.Scope.NamespaceUID || projection.PodUID != w.query.Scope.PodUID || !opener.complete() {
		r.cancel()
		return r, value.ErrUnavailable
	}
	if _, err = r.check(r.ctx); err != nil {
		r.cancel()
		return r, err
	}
	r.mu.Lock()
	if r.ctx.Err() != nil || r.closed {
		r.mu.Unlock()
		r.cancel()
		return r, value.ErrUnavailable
	}
	r.projection = projection
	r.ready = true
	r.mu.Unlock()
	return r, nil
}

func (r *RegionalProjectionRead) shorten(until time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	earliest := identity.Earlier(r.until, until)
	if r.timer == nil || earliest.Before(r.until) {
		r.until = earliest
		if r.timer != nil {
			r.timer.Stop()
		}
		r.timer = time.AfterFunc(time.Until(earliest), r.cancel)
	}
	return !r.closed && r.ctx.Err() == nil && r.worker.now().Before(r.until)
}

// context links both original local ownership and this caller's cancellation.
// Its deadline reflects subsequent monotonic shortening during blocking checks.
func (r *RegionalProjectionRead) context(ctx context.Context) (context.Context, context.CancelFunc) {
	work, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	if r.ctx.Err() != nil {
		cancel()
	}
	return projectionReadContext{Context: work, read: r}, func() { cancel(); stop() }
}

// Repeated current checks may shorten this operation but never refresh its
// original worker proof, claim, authority, key slots or request ownership.
func (r *RegionalProjectionRead) check(ctx context.Context) (value.ContextProjectionAuthority, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || r.ctx.Err() != nil || r.worker.ctx.Err() != nil || r.execution == nil || r.owner.Request() != r.start.Batch.Request {
		return value.ContextProjectionAuthority{}, value.ErrUnavailable
	}
	work, cancel := r.context(ctx)
	defer cancel()
	a, err := r.owner.CheckCurrent(work)
	if err != nil || !r.start.Batch.Current(r.worker.query, a, r.worker.now()) || !r.proof.Matches(r.worker.query, r.worker.worker, r.worker.now()) || !r.shorten(a.ValidUntil) {
		return value.ContextProjectionAuthority{}, value.ErrUnavailable
	}
	actual, err := r.execution.CheckCurrent(work)
	if err != nil || !r.start.Batch.Current(r.worker.query, actual, r.worker.now()) || !sameProjectionAuthority(a, actual) || !r.shorten(actual.ValidUntil) || work.Err() != nil || !r.proof.Matches(r.worker.query, r.worker.worker, r.worker.now()) {
		return value.ContextProjectionAuthority{}, value.ErrUnavailable
	}
	r.mu.Lock()
	a.ValidUntil = identity.Earlier(a.ValidUntil, r.until)
	r.mu.Unlock()
	if !a.Valid(r.worker.now()) {
		return value.ContextProjectionAuthority{}, value.ErrUnavailable
	}
	return a, nil
}

func sameProjectionAuthority(a, b value.ContextProjectionAuthority) bool {
	strip := func(v value.ContextProjectionAuthority) value.ContextProjectionAuthority {
		v.CheckedAt, v.ValidUntil = time.Time{}, time.Time{}
		v.Environment.ObservedAt, v.Environment.ValidUntil = time.Time{}, time.Time{}
		v.Environment.Recovery.ObservedAt, v.Environment.Recovery.FreshUntil = time.Time{}, time.Time{}
		v.Environment.Processing.ObservedAt, v.Environment.Processing.ValidUntil = time.Time{}, time.Time{}
		v.Retention.ObservedAt, v.Retention.ValidUntil = time.Time{}, time.Time{}
		v.AccessUntil, v.DeleteBy = v.AccessUntil.UTC(), v.DeleteBy.UTC()
		return v
	}
	return strip(a) == strip(b)
}

// Projection returns only the fixed approved DTO while this same local read's
// original owner, worker, SQL start and authority remain current.
func (r *RegionalProjectionRead) Projection(ctx context.Context) (value.PodStatusProjection, error) {
	if r == nil {
		return value.PodStatusProjection{}, value.ErrUnavailable
	}
	r.mu.Lock()
	if r.closed || !r.ready || r.checking != nil {
		r.mu.Unlock()
		return value.PodStatusProjection{}, value.ErrUnavailable
	}
	joined := make(chan struct{})
	r.checking = joined
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.checking = nil; close(joined); r.mu.Unlock() }()
	if _, err := r.check(ctx); err != nil {
		return value.PodStatusProjection{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.ready || ctx.Err() != nil || r.ctx.Err() != nil || !r.projection.Valid() {
		return value.PodStatusProjection{}, value.ErrUnavailable
	}
	return r.projection, nil
}

// CloseLocal joins only this exact regional process's work and control handle.
// It can never be supplied to a SQL remote-closure facet. Unknown guard closure
// keeps this process unavailable for another batch, even after lease expiry.
func (r *RegionalProjectionRead) CloseLocal(ctx context.Context) error {
	if r == nil || ctx == nil {
		return value.ErrUnavailable
	}
	r.once.Do(func() {
		cleanupUntil := identity.Earlier(r.worker.query.CleanupUntil, r.start.Batch.Request.Call.WriteUntil)
		cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), cleanupUntil)
		defer cancel()
		r.cancel()
		r.mu.Lock()
		r.closed = true
		r.projection = value.PodStatusProjection{}
		checking := r.checking
		r.mu.Unlock()
		select {
		case <-r.done:
		case <-cleanup.Done():
			r.closeErr = value.ErrUnavailable
			return
		}
		if checking != nil {
			select {
			case <-checking:
			case <-cleanup.Done():
				r.closeErr = value.ErrUnavailable
				return
			}
		}
		// Even an unknown open may return a known handle that must be closed.
		// Its positive local close cannot resolve the unknown admission result.
		var err error
		if r.execution != nil {
			err = r.execution.CloseExecution(cleanup)
		}
		if r.uncertain || r.execution == nil || err != nil || cleanup.Err() != nil {
			r.closeErr = value.ErrUnavailable
			return
		}
		r.worker.mu.Lock()
		r.worker.active = false
		r.worker.mu.Unlock()
	})
	return r.closeErr
}
