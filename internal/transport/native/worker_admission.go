package native

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// HubWorkerAdmission serves the acquisition worker's own native path in the
// hub process (ADR-204 decisions 3 and 9): the download path names the hub
// cluster as its connector cluster, so no connector relays the conversation.
// It checks the worker as ConnectorAdmission does (actual TLS leaf, current
// profile, Pod token, SQL operation) and the hub as HubAdmission does
// (current serving identity, exact owning process and hub configuration),
// then attaches only to this process's own registered operation. It forwards
// nothing: an operation owned by another process, or a path whose connector
// is another cluster, is unavailable here. Every frame repeats both checks.
type HubWorkerAdmission struct {
	peers   NativePeers
	serving NativeHubServing
	router  *HubRouter
	now     func() time.Time
}

func NewHubWorkerAdmission(peers NativePeers, serving NativeHubServing, router *HubRouter, now func() time.Time) (*HubWorkerAdmission, error) {
	if peers == nil || serving == nil || router == nil || now == nil {
		return nil, artifact.ErrInvalid
	}
	return &HubWorkerAdmission{peers, serving, router, now}, nil
}

func (a *HubWorkerAdmission) OpenNative(ctx context.Context, state *tls.ConnectionState, h contracts.NativeHello) (Conversation, error) {
	if a == nil || ctx == nil || state == nil || len(state.PeerCertificates) < 1 || h.Reference.OperationID != "" || h.Reference.Fence != 0 || len(h.WorkerLeaf) != 0 {
		return nil, artifact.ErrInvalid
	}
	serving, e := a.serving.CheckOwnerServing(ctx)
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
	operation := origin.Lease.Operation
	if operation.Path.ConnectorClusterID != operation.Path.HubClusterID {
		return nil, artifact.ErrDownloadUnavailable
	}
	// The exact owning Pod/process and hub configuration, from the current
	// serving identity; another replica's operation is never attached here.
	pathUntil, e := a.serving.CheckNativeHub(call, operation)
	if e != nil {
		return nil, e
	}
	origin.Lease.Until = identity.Earlier(origin.Lease.Until, identity.Earlier(serving, pathUntil))
	if !origin.Lease.Valid(a.now()) || call.Err() != nil {
		return nil, artifact.ErrDownloadExpired
	}
	h.Reference = nativeReference(operation)
	inner, e := a.router.Attach(call, origin, h)
	if e != nil {
		return nil, e
	}
	gate, e := evidence.NewNativeFrameGate(inner.Gate().Context(), func(c context.Context) (value.NativeLease, error) {
		until, e := a.serving.CheckNativeHub(c, operation)
		if e != nil {
			return value.NativeLease{}, e
		}
		peer, e := a.peers.RecheckWorkerNative(c, state, origin)
		if e != nil {
			return peer, e
		}
		local, e := inner.Gate().Check(c)
		if e != nil || !local.Operation.Equal(peer.Operation) || local.Certificate != peer.Certificate || local.Sequence != peer.Sequence {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		local.Until = identity.Earlier(local.Until, identity.Earlier(serving, identity.Earlier(until, peer.Until)))
		return local, nil
	}, a.now)
	if e != nil {
		inner.Close()
		return nil, e
	}
	return &peerConversation{inner, gate}, nil
}
