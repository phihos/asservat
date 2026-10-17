package native

import (
	"context"
	"sync"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
)

// relayReceive watches the owner's response even while the worker is producing
// metadata or bytes. An HTTP client context alone does not observe remote EOF
// when no response-body Read is outstanding. The single receive owner retains
// at most one frame; after the first command only small control frames qualify.
// Cancellation joins that read and clears any undelivered frame.
type relayReceive struct {
	Stream
	gate            *evidence.NativeFrameGate
	ctx             context.Context
	cancel          context.CancelFunc
	next            chan relayReceived
	done            chan struct{}
	once            sync.Once
	stopUpstream    func() bool
	upstreamStopped chan struct{}
}
type relayReceived struct {
	frame contracts.NativeFrame
	err   error
}

func newRelayReceive(gate *evidence.NativeFrameGate, stream Stream) *relayReceive {
	ctx, cancel := context.WithCancel(gate.Context())
	q := &relayReceive{Stream: stream, gate: gate, ctx: ctx, cancel: cancel, next: make(chan relayReceived), done: make(chan struct{}), upstreamStopped: make(chan struct{})}
	// The queued receiver must not mask explicit upstream/process cancellation
	// after buffering Done. A successful final frame stops EOF prefetch only;
	// the actual stream's owned context remains binding through forwarding.
	q.stopUpstream = context.AfterFunc(stream.Context(), func() { cancel(); close(q.upstreamStopped) })
	go q.run()
	return q
}
func (q *relayReceive) run() {
	defer close(q.done)
	first := true
	for {
		// Prefetch cannot authorize delivery. Each nonterminal forward performs
		// its existing complete check; only exact Done uses the terminal snapshot.
		lease, err := q.gate.TerminalLease(q.ctx)
		var frame contracts.NativeFrame
		if err == nil {
			call, stop := context.WithDeadline(q.ctx, lease.Until)
			frame, err = q.Stream.Receive(call)
			stop()
		}
		if err == nil && (first && frame.Kind != contracts.NativeCommandFrame || !first && frame.Kind != contracts.NativeCommitFrame && frame.Kind != contracts.NativeAcknowledgeFrame && frame.Kind != contracts.NativeDoneFrame) {
			err = contracts.ErrNativeProtocol
		}
		if err != nil || q.Stream.Context().Err() != nil {
			clear(frame.Payload)
			// The relay's Context watcher closes the worker, including a blocked key or
			// object read. Do not wait for the main protocol to ask for its next frame.
			q.cancel()
			return
		}
		first = false
		select {
		case q.next <- relayReceived{frame: frame}:
			// A positive final frame must be forwarded before EOF can cancel it. There
			// is no next protocol input after Done; the main owner joins final delivery.
			if frame.Kind == contracts.NativeDoneFrame {
				return
			}
		case <-q.ctx.Done():
			clear(frame.Payload)
			return
		}
	}
}
func (q *relayReceive) Context() context.Context { return q.ctx }
func (q *relayReceive) Receive(ctx context.Context) (contracts.NativeFrame, error) {
	if ctx == nil || ctx.Err() != nil || q.ctx.Err() != nil || q.Stream.Context().Err() != nil {
		return contracts.NativeFrame{}, contracts.ErrNativeProtocol
	}
	select {
	case r := <-q.next:
		if ctx.Err() != nil || q.ctx.Err() != nil || q.Stream.Context().Err() != nil {
			clear(r.frame.Payload)
			return contracts.NativeFrame{}, contracts.ErrNativeProtocol
		}
		return r.frame, r.err
	case <-ctx.Done():
		return contracts.NativeFrame{}, ctx.Err()
	case <-q.ctx.Done():
		return contracts.NativeFrame{}, contracts.ErrNativeProtocol
	}
}
func (q *relayReceive) Close() error {
	q.once.Do(func() {
		q.cancel()
		_ = q.Stream.Close()
		if !q.stopUpstream() {
			<-q.upstreamStopped
		}
	})
	<-q.done
	return nil
}
