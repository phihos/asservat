package mtls

import (
	"context"
	"crypto/tls"
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
type hubConnectorObservationStream interface {
	ExchangeConnectorObservation(context.Context, contracts.ClusterObservationProbe) (contracts.ConnectorObservationReply, error)
	ExchangeClusterObservation(context.Context, value.ClusterObservationRequest) (value.ClusterObservationResult, error)
	CompleteClusterObservation(context.Context, contracts.ClusterObservationReceipt) error
}

// HubConnectorObservation retains one original installed connector pin and
// actual socket. Its constructor admits routing identity only. The single
// observation checks SQL49 independently before metadata and after the result,
// using four genuinely new same-channel source replies around those reads.
type HubConnectorObservation struct {
	ctx           context.Context
	cancel        context.CancelFunc
	pin           value.ConnectorObservationPin
	owner         *OwnerObservationIngress
	registry      app.ConnectorObservationRegistry
	stream        hubConnectorObservationStream
	state         tls.ConnectionState
	exchangeID    string
	now           func() time.Time
	mu            sync.Mutex
	spent, closed bool
	joined        sync.WaitGroup
}

var _ app.ClusterObservationExchange = (*HubConnectorObservation)(nil)

func NewHubConnectorObservation(ctx context.Context, pin value.ConnectorObservationPin, ingress *OwnerObservationIngress, registry app.ConnectorObservationRegistry, stream hubConnectorObservationStream, state *tls.ConnectionState, hello contracts.ClusterObservationHello, now func() time.Time) (*HubConnectorObservation, error) {
	if ctx == nil || ctx.Err() != nil || now == nil || !pin.Valid() || ingress == nil || registry == nil || stream == nil || hello.Format != contracts.ClusterObservationExchangeFormat || !authorization.UUID(hello.ExchangeID) || hello.RootID != pin.Profile.RootID || hello.RootID != ingress.pin.RootID || hello.ClusterID != pin.Profile.Binding.ClusterID {
		return nil, value.ErrInvalid
	}
	// The constructor consumes the accepted socket's original residency. A
	// caller without that retained deadline cannot create a new thirty-second
	// standby interval here, including after delayed bootstrap dispatch.
	originalEnd, finite := ctx.Deadline()
	if !finite || !now().Before(originalEnd) || originalEnd.After(now().Add(30*time.Second)) {
		return nil, value.ErrInvalid
	}
	peer, err := ingress.peer(state)
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
	until := identity.Earlier(originalEnd, peer.NotAfter)
	root, cancel := context.WithDeadline(ctx, until)
	return &HubConnectorObservation{ctx: root, cancel: cancel, pin: pin.Clone(), owner: ingress, registry: registry, stream: stream, state: owned, exchangeID: hello.ExchangeID, now: now}, nil
}

func (h *HubConnectorObservation) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	h.joined.Wait()
}

func (h *HubConnectorObservation) ObserveCluster(ctx context.Context, request value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	var zero value.ClusterObservationResult
	if h == nil || ctx == nil || ctx.Err() != nil || !request.Valid(h.now()) || request.RootID != h.pin.Profile.RootID || request.ClusterID != h.pin.Profile.Binding.ClusterID {
		return zero, value.ErrUnavailable
	}
	h.mu.Lock()
	if h.closed || h.spent || h.ctx.Err() != nil {
		h.mu.Unlock()
		return zero, value.ErrUnavailable
	}
	h.spent = true
	h.joined.Add(1)
	h.mu.Unlock()
	defer h.joined.Done()
	until := identity.Earlier(request.NotAfter, h.now().Add(5*time.Second))
	if d, ok := h.ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	join := linkObservationCancellation(h.ctx, cancel)
	defer join()
	ownerRequest := value.OwnerObservationRequest{RootID: request.RootID, ID: request.ID, Challenge: request.Challenge, RequestedAt: request.RequestedAt, NotAfter: request.NotAfter}
	proofs := &hubConnectorObservationProofs{hub: h, request: ownerObservationRequestWire(ownerRequest)}
	source, err := NewRemoteConnectorObservationSource(call, h.pin, h.owner.pin, ownerRequest, &h.state, proofs, h.now)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	defer source.Close()
	first, err := h.registry.ReadConnectorObservationRegistration(call, h.pin.Profile, source, source.leaf)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	firstEnd, err := source.MatchRegistration(first)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, firstEnd)
	current, stopCurrent := context.WithDeadline(call, until)
	defer stopCurrent()
	result, err := h.stream.ExchangeClusterObservation(current, request.Clone())
	digest, digestErr := app.ClusterObservationRequestDigest(request)
	if err != nil || digestErr != nil || !result.Matches(request, digest, h.now()) || current.Err() != nil {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, result.Interval.FreshUntil)
	final, stopFinal := context.WithDeadline(current, until)
	defer stopFinal()
	last, err := h.registry.ReadConnectorObservationRegistration(final, h.pin.Profile, source, source.leaf)
	if err != nil || last.Certificate != first.Certificate || last.Process != first.Process || last.Revision != first.Revision {
		return zero, value.ErrUnavailable
	}
	lastEnd, err := source.MatchRegistration(last)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, lastEnd)
	completion, stopCompletion := context.WithDeadline(final, until)
	defer stopCompletion()
	receipt := contracts.ClusterObservationReceipt{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: h.exchangeID, RequestID: request.ID, Challenge: request.Challenge, RequestDigest: ownerObservationHex(digest)}
	if completion.Err() != nil || h.stream.CompleteClusterObservation(completion, receipt) != nil {
		return zero, value.ErrUnavailable
	}
	result = result.Restrict(request.RequestedAt, until)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ctx.Err() != nil || completion.Err() != nil || !result.Matches(request, digest, h.now()) {
		return zero, value.ErrUnavailable
	}
	return result, nil
}

type hubConnectorObservationProofs struct {
	hub     *HubConnectorObservation
	request contracts.OwnerObservationRequest
}

func (p *hubConnectorObservationProofs) ReadConnectorObservation(ctx context.Context, ordinal int) (contracts.ConnectorObservationReply, error) {
	if ordinal < 1 || ordinal > contracts.ConnectorObservationChecks {
		return contracts.ConnectorObservationReply{}, value.ErrDenied
	}
	// Own-proof uses the same actual channel and a fresh full owner observation
	// every time. A prior phase's proof is not reused as current authority.
	owner, err := p.hub.owner.ObserveOwnerPeer(ctx, &p.hub.state, p.request)
	if err != nil {
		return contracts.ConnectorObservationReply{}, value.ErrUnavailable
	}
	until := ownerObservationTime(owner.FreshUntil)
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	out, err := p.hub.stream.ExchangeConnectorObservation(call, contracts.ClusterObservationProbe{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: p.hub.exchangeID, Ordinal: ordinal, Owner: owner})
	if err != nil || call.Err() != nil || !p.hub.now().Before(until) {
		return contracts.ConnectorObservationReply{}, value.ErrUnavailable
	}
	return out, nil
}
