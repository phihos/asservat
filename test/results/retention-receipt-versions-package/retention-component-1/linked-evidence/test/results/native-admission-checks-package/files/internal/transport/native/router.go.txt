package native

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"sync"
	"time"
)

// NativeOperationFactory captures the live original hub request/current check.
// It is invoked only after ingress proves the real worker and exact SQL row.
// It never crosses the private wire or recreates a bearer identity.
type NativeOperationFactory func(context.Context, context.Context, evidence.NativeOrigin, contracts.NativeHello) (*HubOperation, error)

// HubRouter retains one local owner per worker, including attachment and joined
// closing. SQL locators are published by the caller only after Register returns.
// Process loss cannot recreate entries from their persisted locator rows.
type HubRouter struct {
	mu      sync.Mutex
	limit   int
	closed  bool
	entries map[string]*NativeRegistration
}
type NativeRegistration struct {
	router            *HubRouter
	operation         value.NativeOperation
	factory           NativeOperationFactory
	ctx               context.Context
	cancel            context.CancelFunc
	mu                sync.Mutex
	attaching, closed bool
	attached          chan struct{}
	ready             chan struct{}
	result            *HubOperation
	err               error
	once              sync.Once
}

func NewHubRouter(limit int) (*HubRouter, error) {
	if limit < 1 || limit > 16 {
		return nil, artifact.ErrInvalid
	}
	return &HubRouter{limit: limit, entries: make(map[string]*NativeRegistration)}, nil
}
func (r *HubRouter) Register(ctx context.Context, o value.NativeOperation, f NativeOperationFactory) (*NativeRegistration, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !o.Valid() || !time.Now().Before(o.Until) || f == nil {
		return nil, artifact.ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || len(r.entries) >= r.limit || r.entries[o.Reference.WorkerID] != nil {
		return nil, artifact.ErrDownloadCapacity
	}
	call, cancel := context.WithDeadline(ctx, o.Until)
	entry := &NativeRegistration{router: r, operation: o, factory: f, ctx: call, cancel: cancel, attached: make(chan struct{}), ready: make(chan struct{})}
	r.entries[o.Reference.WorkerID] = entry
	context.AfterFunc(call, entry.Close)
	return entry, nil
}
func (r *HubRouter) Attach(ctx context.Context, origin evidence.NativeOrigin, h contracts.NativeHello) (Conversation, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !origin.Lease.Valid(time.Now()) || !origin.Proof.Valid(time.Now()) || h.Reference != nativeReference(origin.Lease.Operation) {
		return nil, artifact.ErrDownloadUnavailable
	}
	r.mu.Lock()
	entry := r.entries[h.Reference.WorkerID]
	r.mu.Unlock()
	if entry == nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	return entry.attach(ctx, origin, h)
}
func (r *NativeRegistration) attach(ctx context.Context, origin evidence.NativeOrigin, h contracts.NativeHello) (Conversation, error) {
	r.mu.Lock()
	if r.closed || r.attaching || r.ctx.Err() != nil || !r.operation.Equal(origin.Lease.Operation) {
		r.mu.Unlock()
		return nil, artifact.ErrDownloadUnavailable
	}
	r.attaching = true
	factory := r.factory
	r.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, origin.Lease.Until)
	joined := context.AfterFunc(r.ctx, cancel)
	operation, err := factory(r.ctx, call, origin, h)
	if err == nil && operation != nil {
		checked, e := checkNativeAdmission(call, operation.Gate())
		if e != nil {
			err = e
		} else if lease := checked.lease; !lease.Operation.Equal(r.operation) || lease.Certificate != origin.Lease.Certificate || lease.Sequence != origin.Lease.Sequence || lease.Until.After(origin.Lease.Until) {
			err = artifact.ErrDownloadUnavailable
		} else {
			_, err = operation.attachChecked(checked, h)
		}
	}
	joined()
	cancel()
	// The factory owns its original parent context; the temporary ingress call is
	// only a bounded constructor/check argument, never a new authority lifetime.
	r.mu.Lock()
	if err == nil && (operation == nil || r.closed || r.ctx.Err() != nil || ctx.Err() != nil) {
		err = artifact.ErrDownloadUnavailable
	}
	r.result = operation
	r.err = err
	r.factory = nil
	close(r.attached)
	close(r.ready)
	r.mu.Unlock()
	if err != nil {
		if operation != nil {
			operation.Close()
		}
		return nil, err
	}
	return operation, nil
}
func (r *NativeRegistration) Wait(ctx context.Context) (*HubOperation, error) {
	if r == nil || ctx == nil {
		return nil, artifact.ErrInvalid
	}
	select {
	case <-r.ready:
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closed || r.err != nil || r.result == nil {
			return nil, artifact.ErrDownloadUnavailable
		}
		return r.result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.ctx.Done():
		return nil, artifact.ErrDownloadUnavailable
	}
}
func (r *NativeRegistration) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.cancel()
		attaching := r.attaching
		r.mu.Unlock()
		if attaching {
			<-r.attached
		}
		r.mu.Lock()
		operation := r.result
		r.factory = nil
		r.mu.Unlock()
		if operation != nil {
			operation.Close()
		}
		r.router.mu.Lock()
		if r.router.entries[r.operation.Reference.WorkerID] == r {
			delete(r.router.entries, r.operation.Reference.WorkerID)
		}
		r.router.mu.Unlock()
	})
}
func (r *HubRouter) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	entries := make([]*NativeRegistration, 0, len(r.entries))
	for _, e := range r.entries {
		entries = append(entries, e)
	}
	r.mu.Unlock()
	for _, e := range entries {
		e.Close()
	}
}
