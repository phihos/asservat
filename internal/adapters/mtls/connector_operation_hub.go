package mtls

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// This closed transport implements one actual retained regional stream. It
// cannot choose an address, callback, principal, SQL role or replacement peer.
// Completion removes its exact standby from routing before sending Receipt and
// requires clean request EOF under the original attached bound.
type hubConnectorOperationStream interface {
	ExchangeConnectorObservationOperation(context.Context, contracts.ClusterObservationOperationProbe) (contracts.ConnectorObservationOperationReply, error)
	ExchangeClusterObservation(context.Context, value.ClusterObservationRequest) (value.ClusterObservationResult, error)
	CompleteClusterObservation(context.Context, contracts.ClusterObservationReceipt) error
}

// HubConnectorObservationOperation retains one original installed connector pin and
// actual socket. Its constructor admits routing identity only. The single
// observation borrows the locator-owned native operation once. SQL49 still
// reads around four actual same-channel source values; native brackets are
// explicitly initial/final v2 observations, never hidden legacy full-proof reuse.
type HubConnectorObservationOperation struct {
	ctx           context.Context
	cancel        context.CancelFunc
	pin           value.ConnectorObservationPin
	owner         *OwnerObservationOperationIngress
	registry      app.ConnectorObservationOperationRegistry
	stream        hubConnectorOperationStream
	state         tls.ConnectionState
	exchangeID    string
	now           func() time.Time
	leaf          value.OwnerCertificate
	peer          value.PeerCertificate
	mu            sync.Mutex
	spent, closed bool
	joined        sync.WaitGroup
}

func NewHubConnectorObservationOperation(ctx context.Context, pin value.ConnectorObservationPin, ingress *OwnerObservationOperationIngress, registry app.ConnectorObservationOperationRegistry, stream hubConnectorOperationStream, state *tls.ConnectionState, hello contracts.ClusterObservationHello, now func() time.Time) (*HubConnectorObservationOperation, error) {
	if ctx == nil || ctx.Err() != nil || now == nil || !pin.Valid() || ingress == nil || registry == nil || stream == nil || hello.Format != contracts.ClusterObservationOperationExchangeFormat || !authorization.UUID(hello.ExchangeID) || hello.RootID != pin.Profile.RootID || hello.RootID != ingress.peers.pin.RootID || hello.ClusterID != pin.Profile.Binding.ClusterID {
		return nil, value.ErrInvalid
	}
	// The constructor consumes the accepted socket's original residency. A
	// caller without that retained deadline cannot create a new thirty-second
	// standby interval here, including after delayed bootstrap dispatch.
	originalEnd, finite := ctx.Deadline()
	if !finite || !now().Before(originalEnd) || originalEnd.After(now().Add(30*time.Second)) {
		return nil, value.ErrInvalid
	}
	peer, err := ingress.peers.peer(state)
	if err != nil || peer.Binding != pin.Profile.Binding {
		return nil, value.ErrDenied
	}
	// Preserve the actual exporter but own every verifier-visible certificate.
	safe, err := snapshotOwnerTLS(state)
	if err != nil {
		return nil, err
	}
	owned := *state
	owned.PeerCertificates, owned.VerifiedChains = safe.PeerCertificates, safe.VerifiedChains
	owned.OCSPResponse, owned.SignedCertificateTimestamps = nil, nil
	leaf, err := ingress.peers.server.ServingCertificate()
	if err != nil {
		return nil, err
	}
	until := identity.Earlier(originalEnd, identity.Earlier(peer.NotAfter, leaf.NotAfter))
	root, cancel := context.WithDeadline(ctx, until)
	return &HubConnectorObservationOperation{ctx: root, cancel: cancel, pin: pin.Clone(), owner: ingress, registry: registry, stream: stream, state: owned, exchangeID: hello.ExchangeID, now: now, leaf: leaf, peer: peer}, nil
}

func (h *HubConnectorObservationOperation) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	h.joined.Wait()
}

func (h *HubConnectorObservationOperation) ObserveClusterOperation(ctx context.Context, request value.ClusterObservationRequest, operation *OwnerObservationOperation) (value.ClusterObservationResult, error) {
	var zero value.ClusterObservationResult
	if h == nil || operation == nil || operation.pin != h.owner.peers.pin || operation.server != h.owner.peers.server || ctx == nil || ctx.Err() != nil || !request.Valid(h.now()) || request.RootID != h.pin.Profile.RootID || request.ClusterID != h.pin.Profile.Binding.ClusterID {
		return zero, &operationStep{"request", value.ErrUnavailable}
	}
	h.mu.Lock()
	if h.closed || h.spent || h.ctx.Err() != nil {
		h.mu.Unlock()
		return zero, &operationStep{"spent", value.ErrUnavailable}
	}
	h.spent = true
	h.joined.Add(1)
	h.mu.Unlock()
	defer h.joined.Done()
	success := false
	defer func() {
		if !success {
			operation.fail()
			h.cancel()
		}
	}()
	until := identity.Earlier(request.NotAfter, h.now().Add(5*time.Second))
	if d, ok := h.ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	join := linkObservationCancellation(h.ctx, cancel)
	defer join()
	joinOriginal := linkObservationCancellation(operation.root, cancel)
	defer joinOriginal()
	ownerRequest := value.OwnerObservationRequest{RootID: request.RootID, ID: request.ID, Challenge: request.Challenge, RequestedAt: request.RequestedAt, NotAfter: request.NotAfter}
	if err := operation.attach(call, &h.state, h.exchangeID, h.leaf, h.peer, ownerRequest); err != nil {
		return zero, &operationStep{"attach", err}
	}
	proofs := &hubConnectorOperationProofs{hub: h, operation: operation}
	source, err := NewRemoteConnectorObservationOperationSource(call, h.pin, h.owner.peers.pin, ownerRequest, &h.state, proofs, h.now)
	if err != nil {
		return zero, &operationStep{"source", value.ErrUnavailable}
	}
	defer source.Close()
	first, err := h.registry.ReadConnectorObservationOperation(call, ownerRequest, source, source.leaf, 1)
	if err != nil {
		return zero, &operationStep{"registration-1", err}
	}
	firstEnd, err := source.AcceptRegistration(call, first)
	if err != nil {
		return zero, &operationStep{"accept-1", err}
	}
	until = identity.Earlier(until, firstEnd)
	current, stopCurrent := context.WithDeadline(call, until)
	defer stopCurrent()
	ownerEnd, err := operation.checkRetained(current, false)
	if err != nil {
		return zero, &operationStep{"retained", err}
	}
	until = identity.Earlier(until, ownerEnd)
	currentOwner, stopOwner := context.WithDeadline(current, until)
	defer stopOwner()
	result, err := h.stream.ExchangeClusterObservation(currentOwner, request.Clone())
	digest, digestErr := app.ClusterObservationRequestDigest(request)
	if err != nil || digestErr != nil || !result.Matches(request, digest, h.now()) || current.Err() != nil {
		return zero, &operationStep{"exchange", errors.Join(value.ErrUnavailable, err)}
	}
	ownerEnd, err = operation.checkRetained(currentOwner, false)
	if err != nil {
		return zero, &operationStep{"retained-after", err}
	}
	until = identity.Earlier(until, identity.Earlier(ownerEnd, result.Interval.FreshUntil))
	final, stopFinal := context.WithDeadline(currentOwner, until)
	defer stopFinal()
	last, err := h.registry.ReadConnectorObservationOperation(final, ownerRequest, source, source.leaf, 3)
	if err != nil || last.Registration.Certificate != first.Registration.Certificate || last.Registration.Process != first.Registration.Process || last.Registration.Revision != first.Registration.Revision || !last.FinalMatches(h.pin, ownerRequest, h.now()) || !last.Last.Continues(first.Last) {
		return zero, &operationStep{"registration-3", errors.Join(value.ErrUnavailable, err)}
	}
	lastEnd, err := source.AcceptRegistration(final, last)
	if err != nil {
		return zero, &operationStep{"accept-3", err}
	}
	until = identity.Earlier(until, lastEnd)
	completion, stopCompletion := context.WithDeadline(final, until)
	defer stopCompletion()
	receipt := contracts.ClusterObservationReceipt{Format: contracts.ClusterObservationOperationExchangeFormat, ExchangeID: h.exchangeID, RequestID: request.ID, Challenge: request.Challenge, RequestDigest: ownerObservationHex(digest)}
	receiptEnd, err := operation.CheckFinal(completion)
	if err != nil {
		return zero, &operationStep{"final", err}
	}
	until = identity.Earlier(until, receiptEnd)
	receiptCall, stopReceipt := context.WithDeadline(completion, until)
	defer stopReceipt()
	if receiptCall.Err() != nil || h.stream.CompleteClusterObservation(receiptCall, receipt) != nil {
		return zero, &operationStep{"receipt", value.ErrUnavailable}
	}
	finalEnd, err := operation.CheckFinal(receiptCall)
	if err != nil {
		return zero, &operationStep{"final-receipt", err}
	}
	until = identity.Earlier(until, finalEnd)
	result = result.Restrict(request.RequestedAt, until)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ctx.Err() != nil || receiptCall.Err() != nil || !result.Matches(request, digest, h.now()) {
		return zero, &operationStep{"result", value.ErrUnavailable}
	}
	success = true
	return result, nil
}

// operationStep names the fixed step at which a regional operation was
// refused, for operator diagnostics (FixedStep); it wraps the original error.
type operationStep struct {
	step string
	err  error
}

func (e *operationStep) Error() string { return e.step }
func (e *operationStep) Unwrap() error { return e.err }

// FixedStep appends a nested fixed step, so labels compose across layers.
func (e *operationStep) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}

type hubConnectorOperationProofs struct {
	hub       *HubConnectorObservationOperation
	operation *OwnerObservationOperation
}

func (p *hubConnectorOperationProofs) ReadConnectorObservationOperation(ctx context.Context, ordinal int) (contracts.ConnectorObservationOperationReply, error) {
	var zero contracts.ConnectorObservationOperationReply
	if ordinal < 1 || ordinal > 4 {
		return zero, value.ErrDenied
	}
	peer, err := p.hub.owner.peers.peer(&p.hub.state)
	if err != nil || peer != p.hub.peer {
		return zero, value.ErrUnavailable
	}
	owner, err := p.operation.read(ctx, ordinal)
	if err != nil {
		return zero, err
	}
	until := ownerObservationTime(owner.NativeUntil)
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	out, err := p.hub.stream.ExchangeConnectorObservationOperation(call, contracts.ClusterObservationOperationProbe{Format: contracts.ClusterObservationOperationExchangeFormat, ExchangeID: p.hub.exchangeID, Ordinal: ordinal, Owner: owner})
	current, peerErr := p.hub.owner.peers.peer(&p.hub.state)
	if err != nil || peerErr != nil || current != peer || call.Err() != nil || !p.hub.now().Before(until) {
		return zero, value.ErrUnavailable
	}
	end, err := p.operation.checkRetained(call, false)
	if err != nil {
		return zero, err
	}
	out.NativeUntil = identity.Earlier(ownerObservationTime(out.NativeUntil), end).UTC().Format(time.RFC3339Nano)
	out.SourceFreshUntil = identity.Earlier(ownerObservationTime(out.SourceFreshUntil), end).UTC().Format(time.RFC3339Nano)
	out.WorkloadFreshUntil = identity.Earlier(ownerObservationTime(out.WorkloadFreshUntil), end).UTC().Format(time.RFC3339Nano)
	return out, nil
}
