package evidence

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type workerRouteKey struct{ session, worker string }

// WorkerEnrollmentRouter multiplexes this process's active authenticated control
// requests. It is not a distributed locator, authority cache or durable queue.
// Cross-replica/cluster routing must reach the actual owner over trusted control.
type WorkerEnrollmentRouter struct {
	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	installation string
	bindings     WorkerEnrollmentBindings
	now          func() time.Time
	limit, used  int
	closed       bool
	owners       sync.WaitGroup
	entries      map[workerRouteKey]*WorkerEnrollmentRoute
}

// The handle owns an exact transient operation. Closing it stops new lookups and
// cancels in-flight work/writes, without revoking an already delivered certificate
// or proving worker termination. SQL continues to own all authority and spend.
type WorkerEnrollmentRoute struct {
	router                         *WorkerEnrollmentRouter
	key                            workerRouteKey
	op                             *WorkerEnrollmentOperation
	owner                          *WorkerOwnerRegistration
	ctx                            context.Context
	cancel                         context.CancelFunc
	stopParent, stopRoot, stopDone func() bool
	busy, closed, released         bool // protected by router.mu
}

var _ WorkerEnrollmentExchange = (*WorkerEnrollmentRouter)(nil)

func NewWorkerEnrollmentRouter(ctx context.Context, installation string, bindings WorkerEnrollmentBindings, now func() time.Time, limit int) (*WorkerEnrollmentRouter, error) {
	if ctx == nil || ctx.Err() != nil || !value.UUID(installation) || bindings == nil || now == nil || limit < 1 || limit > 16 {
		return nil, artifact.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	r := &WorkerEnrollmentRouter{ctx: root, cancel: cancel, installation: installation, bindings: bindings, now: now, limit: limit, entries: make(map[workerRouteKey]*WorkerEnrollmentRoute)}
	context.AfterFunc(root, r.Close)
	return r, nil
}

func (r *WorkerEnrollmentRouter) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if r.cancel != nil {
		r.cancel()
	}
	for _, e := range r.entries {
		r.closeLocked(e)
	}
}

// CloseAndJoin is the process dependency boundary. Ordinary Close remains
// cancellation-only for request/context callbacks; after admission is disabled,
// this method also joins registration I/O and every retained busy delivery.
func (r *WorkerEnrollmentRouter) CloseAndJoin() {
	if r == nil {
		return
	}
	r.Close()
	r.owners.Wait()
}

// borrowOwnerWork covers the existing locator wrapper's SQL boundaries, which
// are outside the route's busy delivery interval. It supplies lifetime ownership
// only; each caller retains its unchanged current authority and deadline checks.
func (r *WorkerEnrollmentRouter) borrowOwnerWork() (func(), bool) {
	if r == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil {
		return nil, false
	}
	r.owners.Add(1)
	var once sync.Once
	return func() { once.Do(r.owners.Done) }, true
}

func (r *WorkerEnrollmentRouter) releaseLocked(e *WorkerEnrollmentRoute) {
	if e.closed && !e.busy && !e.released {
		e.released = true
		r.used--
		// Drop the credential-owning operation only after the active call/write
		// has released its ownership. Go does not promise string zeroization.
		e.op = nil
		e.owner = nil
		r.owners.Done()
	}
}
func (r *WorkerEnrollmentRouter) closeLocked(e *WorkerEnrollmentRoute) {
	if !e.closed {
		e.closed = true
		if r.entries[e.key] == e {
			delete(r.entries, e.key)
		}
		e.cancel()
		if e.stopParent != nil {
			e.stopParent()
		}
		if e.stopRoot != nil {
			e.stopRoot()
		}
		if e.stopDone != nil {
			e.stopDone()
		}
	}
	r.releaseLocked(e)
}
func (e *WorkerEnrollmentRoute) Close() {
	if e == nil || e.router == nil {
		return
	}
	r := e.router
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeLocked(e)
}

func workerTarget(w value.DownloadWorker) value.WorkerCredentialTarget {
	return value.WorkerCredentialTarget{InstallationID: w.Binding.InstallationID, SessionID: w.Intent.SessionID, WorkerID: w.Intent.ID, PodUID: w.Binding.PodUID, CreatedAt: w.Intent.CreatedAt, RunUntil: w.Intent.RunUntil}
}
func sameWorkerTarget(a, b value.WorkerCredentialTarget) bool {
	return a.InstallationID == b.InstallationID && a.SessionID == b.SessionID && a.WorkerID == b.WorkerID && a.PodUID == b.PodUID && a.CreatedAt.Equal(b.CreatedAt) && a.RunUntil.Equal(b.RunUntil)
}

// Register accepts only the concrete request-bound operation, never a worker
// callback/principal/credential on the public or private wire. Both current
// human rights and current admitted SQL worker identity precede registration.
func (r *WorkerEnrollmentRouter) Register(ctx context.Context, op *WorkerEnrollmentOperation) (*WorkerEnrollmentRoute, error) {
	if r == nil || r.now == nil || r.ctx == nil || r.bindings == nil || ctx == nil || ctx.Err() != nil || op == nil || op.parent == nil || op.parent.Err() != nil || !op.hasAuthority() || op.service.Now == nil || !op.target.Valid() || !op.scope.Valid() || op.target.InstallationID != r.installation || !r.now().Before(op.bound()) || op.bound().After(r.now().Add(30*time.Second)) {
		return nil, artifact.ErrInvalid
	}
	r.mu.Lock()
	for _, e := range r.entries {
		if e.ctx.Err() != nil || !r.now().Before(e.op.bound()) {
			r.closeLocked(e)
		}
	}
	if r.closed || r.ctx.Err() != nil {
		r.mu.Unlock()
		return nil, artifact.ErrDownloadUnavailable
	}
	if r.used >= r.limit {
		r.mu.Unlock()
		return nil, artifact.ErrDownloadCapacity
	}
	r.used++        // Includes registration I/O and closing operations still in flight.
	r.owners.Add(1) // Under the same admission lock as closed/used.
	r.mu.Unlock()
	accepted := false
	defer func() {
		if !accepted {
			r.mu.Lock()
			r.used--
			r.owners.Done()
			r.mu.Unlock()
		}
	}()
	owner, cancel := context.WithDeadline(ctx, op.bound())
	shorten, finish := workerEffectContext(&owner, op.bound)
	originalCancel := cancel
	cancel = func() { finish(); originalCancel() }
	stopParent := context.AfterFunc(op.parent, cancel)
	stopRoot := context.AfterFunc(r.ctx, cancel)
	defer func() {
		if !accepted {
			stopParent()
			stopRoot()
			cancel()
		}
	}()
	a, err := op.current(owner)
	if err != nil || a.Scope != op.scope || a.Environment.InstallationID != r.installation || !a.Valid(r.now()) || owner.Err() != nil {
		return nil, artifact.ErrDownloadExpired
	}
	shorten()
	o, err := r.bindings.ReadDownloadWorkerEnrollment(owner, op.target.SessionID, op.target.WorkerID)
	if err != nil || !o.Valid(r.now()) || !a.Valid(r.now()) || o.Worker.Intent.Authority.Scope != op.scope || !sameWorkerTarget(workerTarget(o.Worker), op.target) || owner.Err() != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	if op.pinned != nil {
		if _, err = op.current(owner); err != nil {
			return nil, err
		}
	}
	shorten()
	e := &WorkerEnrollmentRoute{router: r, key: workerRouteKey{op.target.SessionID, op.target.WorkerID}, op: op, ctx: owner, cancel: cancel, stopParent: stopParent, stopRoot: stopRoot}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || owner.Err() != nil || !r.now().Before(op.bound()) || !a.Valid(r.now()) || !o.Valid(r.now()) {
		return nil, artifact.ErrDownloadExpired
	}
	if previous := r.entries[e.key]; previous != nil {
		if previous.ctx.Err() != nil || !r.now().Before(previous.op.bound()) {
			r.closeLocked(previous)
		} else {
			return nil, artifact.ErrDownloadConflict
		}
	}
	r.entries[e.key] = e
	accepted = true
	e.stopDone = context.AfterFunc(owner, e.Close)
	return e, nil
}

func (r *WorkerEnrollmentRouter) BeginWorkerEnrollment(ctx context.Context, installation, session, worker string, token, csr []byte) (WorkerEnrollmentDelivery, error) {
	return r.beginWorkerEnrollment(ctx, installation, session, worker, token, csr, nil)
}

func (r *WorkerEnrollmentRouter) beginWorkerEnrollment(ctx context.Context, installation, session, worker string, token, csr []byte, expected *WorkerEnrollmentRoute) (WorkerEnrollmentDelivery, error) {
	if r == nil || r.now == nil || r.ctx == nil || ctx == nil || ctx.Err() != nil || installation != r.installation || !value.UUID(session) || !value.UUID(worker) || len(token) < 1 || len(token) > 16<<10 || len(csr) < 1 || len(csr) > 8192 {
		return nil, artifact.ErrDownloadUnavailable
	}
	r.mu.Lock()
	e := r.entries[workerRouteKey{session, worker}]
	if r.closed || e == nil || expected != nil && e != expected {
		r.mu.Unlock()
		return nil, artifact.ErrDownloadUnavailable
	}
	if e.ctx.Err() != nil || !r.now().Before(e.op.bound()) {
		r.closeLocked(e)
		r.mu.Unlock()
		return nil, artifact.ErrDownloadExpired
	}
	if e.busy {
		r.mu.Unlock()
		return nil, artifact.ErrDownloadConflict
	}
	e.busy = true
	op := e.op
	r.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, op.bound())
	stop := context.AfterFunc(e.ctx, cancel)
	release := func() {
		stop()
		cancel()
		r.mu.Lock()
		defer r.mu.Unlock()
		e.busy = false
		if e.ctx.Err() != nil || !r.now().Before(op.bound()) {
			r.closeLocked(e)
		}
		r.releaseLocked(e)
	}
	d, err := op.BeginWorkerEnrollment(call, installation, session, worker, token, csr)
	if err != nil {
		release()
		return nil, err
	}
	r.mu.Lock()
	valid := !r.closed && !e.closed && call.Err() == nil && e.ctx.Err() == nil && r.now().Before(op.bound())
	r.mu.Unlock()
	if !valid {
		d.Close()
		release()
		return nil, artifact.ErrDownloadExpired
	}
	return &workerEnrollmentDelivery{ctx: d.Context(), certificate: d.Certificate(), release: func() { d.Close(); release() }}, nil
}
