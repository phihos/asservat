package native

import (
	"context"
	"crypto/tls"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type NativePeers interface {
	CheckWorkerNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (evidence.NativeOrigin, error)
	RecheckWorkerNative(context.Context, *tls.ConnectionState, evidence.NativeOrigin) (value.NativeLease, error)
}
type NativeHubServing interface {
	CheckOwnerServing(context.Context) (time.Time, error)
	CheckNativeHub(context.Context, value.NativeOperation) (time.Time, error)
}

type peerConversation struct {
	inner Conversation
	gate  *evidence.NativeFrameGate
}

func (c *peerConversation) Gate() *evidence.NativeFrameGate { return c.gate }
func (c *peerConversation) Serve(ctx context.Context, s Stream) error {
	return c.inner.Serve(ctx, &peerStream{Stream: s, inner: c.inner.Gate(), outer: c.gate})
}

// peerStream carries the operation's exact completion proof across this
// conversation's own frame gate. The operation proves its SQL close against
// its inner gate; the stream sends under the outer peer gate, which is bounded
// by the inner one. Without it every hub-local or relayed conversation was
// refused at its final close (installed native88: serve/close).
type peerStream struct {
	Stream
	inner, outer *evidence.NativeFrameGate
}

func (s *peerStream) sendCompleted(ctx context.Context, f contracts.NativeFrame, proof nativeCompletionProof) error {
	terminal, ok := s.Stream.(interface {
		sendCompleted(context.Context, contracts.NativeFrame, nativeCompletionProof) error
	})
	if !ok || proof.gate == nil || proof.gate != s.inner {
		return step("completion-proof", contracts.ErrNativeProtocol)
	}
	// The peer gate can still hold its valid previous response observation
	// while the inner operation has acknowledged closure at a newer sequence.
	// This is only a zero-byte completion bridge, never a lease for new work.
	inner, innerErr := s.inner.TerminalLease(ctx)
	outer, outerErr := s.outer.TerminalLease(ctx)
	if innerErr != nil || outerErr != nil || !proof.lease.Valid(time.Now()) ||
		!inner.Operation.Equal(proof.lease.Operation) || inner.Certificate != proof.lease.Certificate || inner.Sequence != proof.lease.Sequence ||
		!outer.Operation.Equal(proof.lease.Operation) || outer.Certificate != proof.lease.Certificate || outer.Sequence > proof.lease.Sequence ||
		(outer.Sequence != proof.lease.Sequence && outer.Operation.Kind != value.NativeResponse) {
		return step("completion-lease", contracts.ErrNativeProtocol)
	}
	// Retain all three original cutoffs and the caller's context. Mapping to
	// the exact outer snapshot lets the server keep its strict comparison;
	// it does not claim SQL closed under the older peer observation.
	until := identity.Earlier(proof.lease.Until, identity.Earlier(inner.Until, outer.Until))
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	proof.gate, proof.lease = s.outer, outer
	return terminal.sendCompleted(call, f, proof)
}
func (c *peerConversation) Close() error {
	c.gate.Close()
	e := c.inner.Close()
	_ = c.gate.Wait(context.Background())
	return e
}

// admissionServing is the admission's serving observation as a per-frame
// bound. Each frame's own serving check is current; an approved projection
// conversation (up to the evidence-read window) is not ended by the stale
// admission observation. Other kinds keep it.
func admissionServing(l value.NativeLease, serving time.Time) time.Time {
	if l.Operation.Kind == value.NativeProjection || l.Operation.Kind == value.NativeResponse {
		return l.Operation.Until
	}
	return serving
}
