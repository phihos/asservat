package presentation

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/audit"
)

var ErrOperationDelivery = errors.New("operation delivery unavailable")

// Implemented by the private C-20 adapter around a concrete C-18 delivery. A
// serialized reply/expiry alone never implements this evidence boundary.
type operationReplyGuard interface {
	CheckDisclosure(context.Context) error
	Close(context.Context) error
	Done() <-chan struct{}
}

// Every value copy of OperationReply shares this owner. mu joins disclosure
// checks before Close clears owned bytes; once joins concurrent Close callers.
// Close errors remain errors and do not establish positive remote completion.
type operationReplyOwner struct {
	mu                   sync.Mutex
	once                 sync.Once
	ctx                  context.Context
	guard                operationReplyGuard
	body                 []byte
	digest               [32]byte
	until, cleanupUntil  time.Time
	ack                  func(context.Context, audit.OperationOutcome) error
	acknowledged, closed bool
	cancel               context.CancelFunc
	parentCancel         context.CancelFunc
	release              func()
	err                  error
	lifetimeJoined       <-chan struct{}
}

// Ownership is private to presentation composition; public constructors do not
// accept a caller-supplied guard. ack binds C-18's exact prepared association to
// the existing canonical C-08 outcome after Finish has acknowledged it.
func ownOperationReply(ctx context.Context, reply OperationReply, guard operationReplyGuard, cleanupUntil time.Time, ack func(context.Context, audit.OperationOutcome) error) (OperationReply, error) {
	if ctx == nil || ctx.Err() != nil || guard == nil || ack == nil || reply.owner != nil || len(reply.Body) == 0 || len(reply.Body) > audit.OperationOutputLimit || reply.ValidUntil.IsZero() || cleanupUntil.Before(reply.ValidUntil) {
		return OperationReply{}, ErrOperationDelivery
	}
	deadline, ok := ctx.Deadline()
	if !ok || reply.ValidUntil.After(deadline) {
		return OperationReply{}, ErrOperationDelivery
	}
	done := guard.Done()
	if done == nil {
		return OperationReply{}, ErrOperationDelivery
	}
	select {
	case <-done:
		return OperationReply{}, ErrOperationDelivery
	default:
	}
	owned, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	// The application owns a child of the original request. Its cancellation
	// cannot otherwise propagate upward into a blocked public socket write.
	// Exactly one watcher belongs to this shared reply owner and Close joins it.
	go func() {
		defer close(joined)
		select {
		case <-done:
			cancel()
		case <-owned.Done():
		}
	}()
	reply.owner = &operationReplyOwner{ctx: owned, cancel: cancel, guard: guard, body: reply.Body, digest: sha256.Sum256(reply.Body), until: reply.ValidUntil, cleanupUntil: cleanupUntil, ack: ack, lifetimeJoined: joined}
	return reply, nil
}

// ResponseContext combines transport cancellation with the original live
// application owner. It grants no authority and cannot extend either deadline.
// The caller joins the returned callback before closing the reply/reusing the
// socket, after WriteOperationResponse has joined its own deadline callback.
func (r OperationReply) ResponseContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.owner == nil {
		return ctx, func() {}
	}
	o := r.owner
	o.mu.Lock()
	until := o.until
	o.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, until)
	joined := make(chan struct{})
	stop := context.AfterFunc(o.ctx, func() { cancel(); close(joined) })
	var once sync.Once
	return call, func() {
		once.Do(func() {
			cancel()
			if !stop() {
				<-joined
			}
		})
	}
}

func (r OperationReply) CheckDisclosure(ctx context.Context) error {
	if r.owner == nil {
		return nil
	} // Existing metadata-only operations.
	o := r.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if r.ValidUntil.IsZero() {
		return ErrOperationDelivery
	}
	if r.ValidUntil.Before(o.until) {
		o.until = r.ValidUntil
	}
	if ctx == nil || ctx.Err() != nil || o.ctx.Err() != nil || o.closed || !o.acknowledged || !time.Now().Before(o.until) || sha256.Sum256(r.Body) != o.digest {
		return ErrOperationDelivery
	}
	call, cancel := context.WithDeadline(ctx, o.until)
	defer cancel()
	joined := make(chan struct{})
	stop := context.AfterFunc(o.ctx, func() { cancel(); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	if err := o.guard.CheckDisclosure(call); err != nil || call.Err() != nil || o.ctx.Err() != nil || !time.Now().Before(o.until) || sha256.Sum256(r.Body) != o.digest {
		return ErrOperationDelivery
	}
	return nil
}

func (r OperationReply) acknowledge(ctx context.Context, out audit.OperationOutcome) error {
	if r.owner == nil {
		return nil
	}
	o := r.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.acknowledged || out.OutputBytes != int64(len(r.Body)) || sha256.Sum256(r.Body) != o.digest || out.MetadataUntil.After(o.until) {
		return ErrOperationDelivery
	}
	if err := o.ack(ctx, out); err != nil {
		return ErrOperationDelivery
	}
	o.until = out.MetadataUntil
	o.acknowledged = true
	return nil
}

// transfer runs only immediately before returning a successful owned reply.
// Cleanup cannot extend the original invocation's write/cleanup allowance.
func (r OperationReply) transfer(cancel context.CancelFunc, release func(), cleanupUntil time.Time) {
	o := r.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	o.parentCancel, o.release = cancel, release
	if cleanupUntil.Before(o.cleanupUntil) {
		o.cleanupUntil = cleanupUntil
	}
}

func (r OperationReply) boundCleanup(until time.Time) {
	if r.owner == nil {
		return
	}
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	if until.Before(r.owner.cleanupUntil) {
		r.owner.cleanupUntil = until
	}
}

// Close is cleanup only: cancellation is detached but the original finite
// cleanup cutoff survives. This layer creates the bounded cleanup context;
// callers may pass their canceled/expired public request without shortening
// cleanup to that expired disclosure interval. The guard must join
// its local work even when it reports uncertain remote closure. No retry here
// converts a timeout into a positive completion or refills charged resources.
func (r OperationReply) Close(ctx context.Context) error {
	if r.owner == nil {
		return nil
	}
	o := r.owner
	o.once.Do(func() {
		// Cancel before waiting for an in-flight disclosure check to return.
		o.cancel()
		<-o.lifetimeJoined
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.parentCancel != nil {
			o.parentCancel()
		}
		o.closed = true
		until := o.cleanupUntil
		if ctx == nil {
			ctx = context.Background()
		}
		cleanup, stop := context.WithDeadline(context.WithoutCancel(ctx), until)
		o.err = o.guard.Close(cleanup)
		if cleanup.Err() != nil && o.err == nil {
			o.err = ErrOperationDelivery
		}
		stop()
		clear(o.body)
		if o.release != nil {
			o.release()
		}
	})
	return o.err
}

type operationAuditEffect uint8

const (
	operationEffectUnspecified operationAuditEffect = iota
	operationEffectNone
	operationEffectAccepted
	operationEffectUnknown
)
