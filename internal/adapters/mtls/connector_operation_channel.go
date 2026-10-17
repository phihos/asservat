package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorObservationOperationChannel belongs to one actual regional TLS stream. Its
// methods implement four real source-value replies within two native brackets,
// one bounded local metadata
// read and the exact final receipt. The transport still owns framing/socket
// cancellation and must join both this channel and the actual stream at Close.
// A standby candidate authenticates only the handshake, not later metadata.
type ConnectorObservationOperationChannel struct {
	ctx                                  context.Context
	cancel                               context.CancelFunc
	exchangeID                           string
	pin                                  value.OwnerObservationPin
	state                                tls.ConnectionState
	owner                                value.OwnerCertificate
	leaf                                 value.ConnectorCredentialCertificate
	keys                                 connectorObservationKeys
	verifier                             *OwnerPeerVerifier
	candidates                           *app.OwnerObservationCandidateSelection
	registry                             app.OwnerCertificateRegistry
	producer                             *ConnectorObservationOperationProducer
	metadata                             app.ClusterObservationExchange
	now                                  func() time.Time
	mu                                   sync.Mutex
	busy, failed, closed, read, received bool
	ordinal                              int
	request                              value.OwnerObservationRequest
	origin                               *ownerOperationObservation
	operation                            *connectorProducedOperation
	lastOwner                            *ownerOperationObservation
	digest                               artifact.Digest
	until                                time.Time
	untilBy                              string
	joined                               sync.WaitGroup
}

func NewConnectorObservationOperationChannel(ctx context.Context, exchangeID string, pin value.OwnerObservationPin, roots *x509.CertPool, before value.APIContextOwnerCandidates, state *tls.ConnectionState, leaf value.ConnectorCredentialCertificate, producer *ConnectorObservationOperationProducer, candidates *app.OwnerObservationCandidateSelection, registry app.OwnerCertificateRegistry, metadata app.ClusterObservationExchange, now func() time.Time) (*ConnectorObservationOperationChannel, error) {
	if ctx == nil || ctx.Err() != nil || !authorization.UUID(exchangeID) || !pin.Valid() || roots == nil || len(roots.Subjects()) == 0 || producer == nil || !candidates.BoundTo(pin.Pool) || registry == nil || metadata == nil || now == nil || !before.Valid(now()) || before.Pool != pin.Pool || !leaf.Valid(now()) || leaf.Usage != "client" || producer.pin.Profile.RootID != pin.RootID || leaf.Binding != producer.pin.Profile.Binding {
		return nil, value.ErrInvalid
	}
	verifier, err := NewOwnerPeerVerifierForPool(roots, pin.Pool, now)
	if err != nil {
		return nil, err
	}
	owner, err := verifier.VerifyBootstrapServer(state, before)
	if err != nil {
		return nil, err
	}
	safe, err := snapshotOwnerTLS(state)
	if err != nil {
		return nil, err
	}
	// Retain the actual export function from this connection while replacing
	// all verifier-visible DER with owned parsed copies. No peer field supplies
	// an exporter, roots, candidate or alternate TLS state.
	owned := *state
	owned.PeerCertificates = safe.PeerCertificates
	owned.VerifiedChains = safe.VerifiedChains
	owned.OCSPResponse = nil
	owned.SignedCertificateTimestamps = nil
	keys, err := producer.credentials.observationKeys(ctx, leaf)
	if err != nil {
		return nil, err
	}
	originalEnd, finite := ctx.Deadline()
	if !finite || !now().Before(originalEnd) || originalEnd.After(now().Add(30*time.Second)) {
		return nil, value.ErrInvalid
	}
	until := identity.Earlier(originalEnd, identity.Earlier(owner.NotAfter, identity.Earlier(leaf.NotAfter, keys.runUntil)))
	root, cancel := context.WithDeadline(ctx, until)
	return &ConnectorObservationOperationChannel{ctx: root, cancel: cancel, exchangeID: exchangeID, pin: pin, state: owned, owner: owner, leaf: leaf, keys: keys, verifier: verifier, candidates: candidates, registry: registry, producer: producer, metadata: metadata, now: now, until: until, untilBy: "connection"}, nil
}

func (c *ConnectorObservationOperationChannel) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	c.joined.Wait()
	c.mu.Lock()
	operation := c.operation
	c.mu.Unlock()
	if operation != nil {
		operation.Close()
	}
}

// enter spends a phase before any blocking call. Any failed/unknown phase is
// terminal; no repeated proof, metadata read or receipt can restart its bounds.
func (c *ConnectorObservationOperationChannel) enter(ctx context.Context, kind contracts.ClusterObservationFrameKind, ordinal int) (context.Context, func(bool), error) {
	if c == nil {
		return nil, nil, value.ErrUnavailable
	}
	c.mu.Lock()
	end, finite := time.Time{}, false
	if ctx != nil {
		end, finite = ctx.Deadline()
	}
	if ctx == nil || ctx.Err() != nil || !finite || c.busy || c.failed || c.closed || c.received || c.ctx.Err() != nil || !c.now().Before(c.until) {
		c.failed = true
		c.cancel()
		c.mu.Unlock()
		return nil, nil, value.ErrUnavailable
	}
	valid := false
	switch kind {
	case contracts.ClusterObservationProbeFrame:
		valid = ordinal == c.ordinal+1 && ordinal <= 4 && (ordinal <= 2 && !c.read || ordinal >= 3 && c.read)
	case contracts.ClusterObservationReadFrame:
		valid = c.ordinal == 2 && !c.read
	case contracts.ClusterObservationReceiptFrame:
		valid = c.ordinal == 4 && c.read
	}
	if !valid {
		c.failed = true
		c.cancel()
		c.mu.Unlock()
		return nil, nil, value.ErrDenied
	}
	c.busy = true
	if kind == contracts.ClusterObservationProbeFrame {
		c.ordinal = ordinal
	}
	if kind == contracts.ClusterObservationReadFrame {
		c.read = true
	}
	c.narrow(end, "call")
	until := c.until
	c.joined.Add(1)
	c.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, until)
	done := make(chan struct{})
	stop := context.AfterFunc(c.ctx, func() { cancel(); close(done) })
	finish := func(success bool) {
		if !stop() {
			<-done
		}
		cancel()
		c.mu.Lock()
		c.busy = false
		if !success {
			c.failed = true
			c.cancel()
		}
		c.mu.Unlock()
		c.joined.Done()
	}
	if c.producer.credentials.observationKeysCurrent(call, c.keys) != nil {
		finish(false)
		return nil, nil, value.ErrUnavailable
	}
	return call, finish, nil
}

// narrow shortens the channel's interval and records which bound set it, for
// the window refusal's diagnostic step. The caller holds c.mu.
func (c *ConnectorObservationOperationChannel) narrow(t time.Time, by string) {
	if t.Before(c.until) {
		c.until, c.untilBy = t, by
	}
}

func (c *ConnectorObservationOperationChannel) AnswerConnectorObservation(ctx context.Context, p contracts.ClusterObservationOperationProbe) (contracts.ConnectorObservationOperationReply, error) {
	var zero contracts.ConnectorObservationOperationReply
	if c == nil || p.Format != contracts.ClusterObservationOperationExchangeFormat || p.ExchangeID != c.exchangeID {
		if c != nil {
			c.fail()
		}
		return zero, answerStep("probe", value.ErrDenied, nil)
	}
	r, err := observationOperationRequest(p.Owner.Request, c.now())
	if err != nil || r.RootID != c.pin.RootID {
		c.fail()
		return zero, answerStep("request", value.ErrDenied, err)
	}
	call, finish, err := c.enter(ctx, contracts.ClusterObservationProbeFrame, p.Ordinal)
	if err != nil {
		return zero, answerStep("enter", err, nil)
	}
	success := false
	defer func() { finish(success) }()
	c.mu.Lock()
	if c.request.ID != "" && !sameConnectorObservationRequest(c.request, r) {
		c.mu.Unlock()
		return zero, answerStep("same-request", value.ErrDenied, nil)
	}
	if c.request.ID == "" {
		c.request = r
		c.narrow(r.NotAfter, "request")
	}
	until := c.until
	c.mu.Unlock()
	call, stop := context.WithDeadline(call, until)
	defer stop()
	// The original handshake candidate cannot authorize a request arriving after
	// passive residency. Read current candidates without changing the selected
	// actual owner/leaf, then independently check current registration and roots.
	current, err := c.candidates.ReadOwnerObservationCandidates(call)
	if err != nil || current.Pool != c.pin.Pool || !current.Valid(c.now()) {
		return zero, answerStep("candidates", value.ErrUnavailable, err)
	}
	peer := value.PeerCertificate{Binding: c.leaf.Binding, Digest: c.leaf.Digest, NotBefore: c.leaf.NotBefore, NotAfter: c.leaf.NotAfter}
	owner, err := checkOwnerOperation(call, &c.state, c.verifier, c.registry, current, c.pin, r, peer, p.Owner, p.Ordinal, c.now)
	if err != nil || owner.owner != c.owner {
		return zero, answerStep("owner", value.ErrUnavailable, err)
	}
	c.mu.Lock()
	if c.origin != nil && !owner.continues(*c.origin) {
		c.mu.Unlock()
		return zero, answerStep("owner-continues", value.ErrUnavailable, nil)
	}
	if c.origin == nil {
		original := owner
		c.origin = &original
	}
	c.narrow(owner.until, "owner")
	saved := owner
	c.lastOwner = &saved
	until = c.until
	c.mu.Unlock()
	bounded, narrow := context.WithDeadline(call, until)
	defer narrow()
	operation := c.operation
	if p.Ordinal == 1 {
		operation, err = c.producer.begin(c.ctx, bounded, &c.state, c.leaf, r)
		if err != nil {
			return zero, answerStep("begin", value.ErrUnavailable, err)
		}
		c.mu.Lock()
		c.operation = operation
		c.mu.Unlock()
	}
	if operation == nil {
		return zero, answerStep("operation", value.ErrUnavailable, nil)
	}
	reply, err := operation.read(bounded, p.Ordinal)
	if err != nil || bounded.Err() != nil {
		return zero, answerStep("read", value.ErrUnavailable, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.narrow(ownerObservationTime(reply.NativeUntil), "native")
	currentKeys, stopCurrent := context.WithDeadline(bounded, c.until)
	defer stopCurrent()
	if c.closed || c.failed || c.ctx.Err() != nil || !c.now().Before(c.until) || c.producer.credentials.observationKeysCurrent(currentKeys, c.keys) != nil {
		step := "keys"
		if !c.now().Before(c.until) {
			step = "window-" + c.untilBy
		}
		return zero, answerStep(step, value.ErrUnavailable, nil)
	}
	reply.NativeUntil = c.until.UTC().Format(time.RFC3339Nano)
	reply.SourceFreshUntil = identity.Earlier(ownerObservationTime(reply.SourceFreshUntil), c.until).UTC().Format(time.RFC3339Nano)
	reply.WorkloadFreshUntil = identity.Earlier(ownerObservationTime(reply.WorkloadFreshUntil), c.until).UTC().Format(time.RFC3339Nano)
	success = true
	return reply, nil
}

func (c *ConnectorObservationOperationChannel) ObserveCluster(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	var zero value.ClusterObservationResult
	if c == nil || !r.Valid(c.now()) || r.RootID != c.pin.RootID || r.ClusterID != c.producer.pin.Profile.Binding.ClusterID {
		if c != nil {
			c.fail()
		}
		return zero, value.ErrDenied
	}
	call, finish, err := c.enter(ctx, contracts.ClusterObservationReadFrame, 0)
	if err != nil {
		return zero, err
	}
	success := false
	defer func() { finish(success) }()
	c.mu.Lock()
	original := c.request
	c.mu.Unlock()
	if !sameConnectorObservationRequest(original, value.OwnerObservationRequest{RootID: r.RootID, ID: r.ID, Challenge: r.Challenge, RequestedAt: r.RequestedAt, NotAfter: r.NotAfter}) {
		return zero, value.ErrDenied
	}
	if err := c.checkSelectedOwner(call); err != nil {
		return zero, err
	}
	c.mu.Lock()
	metadataEnd := c.until
	c.mu.Unlock()
	bounded, stop := context.WithDeadline(call, metadataEnd)
	defer stop()
	result, err := c.metadata.ObserveCluster(bounded, r.Clone())
	if err != nil || call.Err() != nil {
		return zero, value.ErrUnavailable
	}
	if err := c.checkSelectedOwner(bounded); err != nil {
		return zero, err
	}
	c.mu.Lock()
	until := c.until
	c.mu.Unlock()
	current, stopCurrent := context.WithDeadline(bounded, until)
	defer stopCurrent()
	digest, err := app.ClusterObservationRequestDigest(r)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	result = result.Restrict(original.RequestedAt, until)
	if !result.Matches(r, digest, c.now()) {
		return zero, value.ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.failed || c.ctx.Err() != nil || !c.now().Before(c.until) || c.producer.credentials.observationKeysCurrent(current, c.keys) != nil {
		return zero, value.ErrUnavailable
	}
	c.digest = digest
	c.narrow(result.Interval.FreshUntil, "result")
	success = true
	return result, nil
}

func (c *ConnectorObservationOperationChannel) AcceptObservationReceipt(ctx context.Context, r contracts.ClusterObservationReceipt) error {
	call, finish, err := c.enter(ctx, contracts.ClusterObservationReceiptFrame, 0)
	if err != nil {
		return err
	}
	success := false
	defer func() { finish(success) }()
	if err := c.checkSelectedOwner(call); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	current, stopCurrent := context.WithDeadline(call, c.until)
	defer stopCurrent()
	if r.Format != contracts.ClusterObservationOperationExchangeFormat || r.ExchangeID != c.exchangeID || r.RequestID != c.request.ID || r.Challenge != c.request.Challenge || r.RequestDigest != ownerObservationHex(c.digest) || c.digest == (artifact.Digest{}) || c.closed || c.failed || call.Err() != nil || c.ctx.Err() != nil || !c.now().Before(c.until) || c.producer.credentials.observationKeysCurrent(current, c.keys) != nil {
		return value.ErrDenied
	}
	c.received = true
	success = true
	return nil
}

// A retained numbered own proof supplies only its original native bracket. Each
// metadata/receipt boundary still reads current candidates/SQL and actual TLS.
func (c *ConnectorObservationOperationChannel) checkSelectedOwner(ctx context.Context) error {
	c.mu.Lock()
	last, until := c.lastOwner, c.until
	closed := c.closed || c.failed || c.ctx.Err() != nil
	c.mu.Unlock()
	if last == nil || ctx == nil || ctx.Err() != nil || closed || !c.now().Before(until) {
		return value.ErrUnavailable
	}
	// Every previously observed cap reaches the next actual candidate/SQL
	// read immediately. A later caller cannot renew this operation's bound.
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	candidates, err := c.candidates.ReadOwnerObservationCandidates(call)
	if err != nil {
		return err
	}
	peer := value.PeerCertificate{Binding: c.leaf.Binding, Digest: c.leaf.Digest, NotBefore: c.leaf.NotBefore, NotAfter: c.leaf.NotAfter}
	checked, err := checkOwnerOperation(call, &c.state, c.verifier, c.registry, candidates, c.pin, c.request, peer, last.wire, last.wire.Ordinal, c.now)
	if err != nil || !checked.continues(*last) {
		return value.ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.narrow(checked.until, "owner-check")
	if c.closed || c.failed || c.ctx.Err() != nil || call.Err() != nil || ctx.Err() != nil || !c.now().Before(c.until) {
		return value.ErrUnavailable
	}
	return nil
}

func (c *ConnectorObservationOperationChannel) fail() {
	c.mu.Lock()
	c.failed = true
	c.cancel()
	c.mu.Unlock()
}
