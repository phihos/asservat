package native

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/tls"
	"errors"
	"time"
)

type NativePeers interface {
	CheckWorkerNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (evidence.NativeOrigin, error)
	CheckForwardedNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (evidence.NativeOrigin, error)
	RecheckWorkerNative(context.Context, *tls.ConnectionState, evidence.NativeOrigin) (value.NativeLease, error)
	RecheckForwardedNative(context.Context, *tls.ConnectionState, evidence.NativeOrigin) (value.NativeLease, error)
}
type NativeOwnerForwarder interface {
	OpenNativeOwner(context.Context, evidence.NativeOrigin, contracts.NativeHello) (contracts.NativeStream, *evidence.NativeFrameGate, error)
}
type NativeConnectorServing interface {
	CheckNativeConnector(context.Context) (time.Time, error)
}
type NativeHubServing interface {
	CheckOwnerServing(context.Context) (time.Time, error)
	CheckNativeHub(context.Context, value.NativeOperation) (time.Time, error)
}

type ConnectorAdmission struct {
	peers   NativePeers
	serving NativeConnectorServing
	forward NativeOwnerForwarder
	now     func() time.Time
}

func NewConnectorAdmission(peers NativePeers, serving NativeConnectorServing, forward NativeOwnerForwarder, now func() time.Time) (*ConnectorAdmission, error) {
	if peers == nil || serving == nil || forward == nil || now == nil {
		return nil, artifact.ErrInvalid
	}
	return &ConnectorAdmission{peers, serving, forward, now}, nil
}
func (a *ConnectorAdmission) OpenNative(ctx context.Context, state *tls.ConnectionState, h contracts.NativeHello) (Conversation, error) {
	if a == nil || ctx == nil || state == nil || len(state.PeerCertificates) < 1 || h.Reference.OperationID != "" || h.Reference.Fence != 0 || len(h.WorkerLeaf) != 0 {
		return nil, artifact.ErrInvalid
	}
	serving, e := a.serving.CheckNativeConnector(ctx)
	if e != nil {
		return nil, e
	}
	call, stop := context.WithDeadline(ctx, serving)
	defer stop()
	origin, e := a.peers.CheckWorkerNative(call, state, h)
	var idle *evidence.NativeIdle
	if errors.As(e, &idle) && idle != nil {
		idle.Until = identity.Earlier(idle.Until, serving)
		if idle.Valid(a.now()) && call.Err() == nil {
			return nil, idle
		}
		return nil, artifact.ErrDownloadUnavailable
	}
	if e != nil {
		return nil, e
	}
	h.Reference = nativeReference(origin.Lease.Operation)
	h.WorkerLeaf = append([]byte(nil), state.PeerCertificates[0].Raw...)
	defer clear(h.WorkerLeaf)
	// OpenNativeOwner rechecks the current locator and actual exact hub peer
	// before forwarding the dedicated Pod token. It never receives a human token.
	origin.Lease.Until = identity.Earlier(origin.Lease.Until, serving)
	upstream, remote, e := a.forward.OpenNativeOwner(ctx, origin, h)
	if e != nil {
		return nil, e
	}
	gate, e := evidence.NewNativeFrameGate(ctx, func(c context.Context) (value.NativeLease, error) {
		until, e := a.serving.CheckNativeConnector(c)
		if e != nil {
			return value.NativeLease{}, e
		}
		local, e := a.peers.RecheckWorkerNative(c, state, origin)
		if e != nil {
			return local, e
		}
		other, e := remote.Check(c)
		if e != nil || !other.Operation.Equal(local.Operation) || other.Certificate != local.Certificate || other.Sequence != local.Sequence {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		local.Until = identity.Earlier(local.Until, identity.Earlier(admissionServing(local, serving), identity.Earlier(until, other.Until)))
		return local, nil
	}, a.now)
	if e != nil {
		upstream.Close()
		remote.Close()
		_ = remote.Wait(context.Background())
		return nil, e
	}
	relay, e := NewRelayConversation(gate, upstream)
	if e != nil {
		gate.Close()
		upstream.Close()
		remote.Close()
		_ = gate.Wait(context.Background())
		_ = remote.Wait(context.Background())
		return nil, e
	}
	return &gatedRelay{RelayConversation: relay, remote: remote}, nil
}

type gatedRelay struct {
	*RelayConversation
	remote *evidence.NativeFrameGate
}

func (c *gatedRelay) Close() error {
	e := c.RelayConversation.Close()
	c.remote.Close()
	_ = c.remote.Wait(context.Background())
	return e
}

type HubAdmission struct {
	peers   NativePeers
	serving NativeHubServing
	router  *HubRouter
	now     func() time.Time
}

func NewHubAdmission(peers NativePeers, serving NativeHubServing, router *HubRouter, now func() time.Time) (*HubAdmission, error) {
	if peers == nil || serving == nil || router == nil || now == nil {
		return nil, artifact.ErrInvalid
	}
	return &HubAdmission{peers, serving, router, now}, nil
}
func (a *HubAdmission) OpenNative(ctx context.Context, state *tls.ConnectionState, h contracts.NativeHello) (Conversation, error) {
	if a == nil || ctx == nil || state == nil {
		return nil, artifact.ErrInvalid
	}
	serving, e := a.serving.CheckOwnerServing(ctx)
	if e != nil {
		return nil, e
	}
	call, stop := context.WithDeadline(ctx, serving)
	defer stop()
	origin, e := a.peers.CheckForwardedNative(call, state, h)
	if e != nil {
		return nil, e
	}
	pathUntil, e := a.serving.CheckNativeHub(call, origin.Lease.Operation)
	if e != nil {
		return nil, e
	}
	origin.Lease.Until = identity.Earlier(origin.Lease.Until, pathUntil)
	inner, e := a.router.Attach(call, origin, h)
	if e != nil {
		return nil, e
	}
	gate, e := evidence.NewNativeFrameGate(inner.Gate().Context(), func(c context.Context) (value.NativeLease, error) {
		until, e := a.serving.CheckNativeHub(c, origin.Lease.Operation)
		if e != nil {
			return value.NativeLease{}, e
		}
		peer, e := a.peers.RecheckForwardedNative(c, state, origin)
		if e != nil {
			return peer, e
		}
		local, e := inner.Gate().Check(c)
		if e != nil || !local.Operation.Equal(peer.Operation) || local.Certificate != peer.Certificate || local.Sequence != peer.Sequence {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		local.Until = identity.Earlier(local.Until, identity.Earlier(admissionServing(local, serving), identity.Earlier(until, peer.Until)))
		return local, nil
	}, a.now)
	if e != nil {
		inner.Close()
		return nil, e
	}
	return &peerConversation{inner, gate}, nil
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
	proof.gate = s.outer
	return terminal.sendCompleted(ctx, f, proof)
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
	if l.Operation.Kind == value.NativeProjection {
		return l.Operation.Until
	}
	return serving
}
