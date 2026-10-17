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

// ConnectorObservationChannel belongs to one actual regional TLS stream. Its
// methods implement only four fresh proof replies, one bounded local metadata
// read and the exact final receipt. The transport still owns framing/socket
// cancellation and must join both this channel and the actual stream at Close.
// A standby candidate authenticates only the handshake, not later metadata.
type ConnectorObservationChannel struct {
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
	producer                             *ConnectorObservationProducer
	metadata                             app.ClusterObservationExchange
	now                                  func() time.Time
	mu                                   sync.Mutex
	busy, failed, closed, read, received bool
	ordinal                              int
	request                              value.OwnerObservationRequest
	origin                               *value.OwnerObservation
	digest                               artifact.Digest
	until                                time.Time
	joined                               sync.WaitGroup
}

func NewConnectorObservationChannel(ctx context.Context, exchangeID string, pin value.OwnerObservationPin, roots *x509.CertPool, before value.APIContextOwnerCandidates, state *tls.ConnectionState, leaf value.ConnectorCredentialCertificate, producer *ConnectorObservationProducer, candidates *app.OwnerObservationCandidateSelection, registry app.OwnerCertificateRegistry, metadata app.ClusterObservationExchange, now func() time.Time) (*ConnectorObservationChannel, error) {
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
	until := identity.Earlier(now().Add(30*time.Second), identity.Earlier(owner.NotAfter, identity.Earlier(leaf.NotAfter, keys.runUntil)))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	root, cancel := context.WithDeadline(ctx, until)
	return &ConnectorObservationChannel{ctx: root, cancel: cancel, exchangeID: exchangeID, pin: pin, state: owned, owner: owner, leaf: leaf, keys: keys, verifier: verifier, candidates: candidates, registry: registry, producer: producer, metadata: metadata, now: now, until: until}, nil
}

func (c *ConnectorObservationChannel) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	c.joined.Wait()
}

// enter spends a phase before any blocking call. Any failed/unknown phase is
// terminal; no repeated proof, metadata read or receipt can restart its bounds.
func (c *ConnectorObservationChannel) enter(ctx context.Context, kind contracts.ClusterObservationFrameKind, ordinal int) (context.Context, func(bool), error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, value.ErrUnavailable
	}
	c.mu.Lock()
	if c.busy || c.failed || c.closed || c.received || c.ctx.Err() != nil || !c.now().Before(c.until) {
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

func (c *ConnectorObservationChannel) AnswerConnectorObservation(ctx context.Context, p contracts.ClusterObservationProbe) (contracts.ConnectorObservationReply, error) {
	var zero contracts.ConnectorObservationReply
	if c == nil || p.Format != contracts.ClusterObservationExchangeFormat || p.ExchangeID != c.exchangeID {
		return zero, value.ErrDenied
	}
	r, err := ownerObservationRequest(p.Owner.Request, c.now())
	if err != nil || r.RootID != c.pin.RootID {
		return zero, value.ErrDenied
	}
	call, finish, err := c.enter(ctx, contracts.ClusterObservationProbeFrame, p.Ordinal)
	if err != nil {
		return zero, err
	}
	success := false
	defer func() { finish(success) }()
	c.mu.Lock()
	if c.request.ID != "" && !sameConnectorObservationRequest(c.request, r) {
		c.mu.Unlock()
		return zero, value.ErrDenied
	}
	if c.request.ID == "" {
		c.request = r
		c.until = identity.Earlier(c.until, r.NotAfter)
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
		return zero, value.ErrUnavailable
	}
	peer := value.PeerCertificate{Binding: c.leaf.Binding, Digest: c.leaf.Digest, NotBefore: c.leaf.NotBefore, NotAfter: c.leaf.NotAfter}
	owner, err := checkOwnerObservation(call, &c.state, c.verifier, c.registry, current, c.pin, r, peer, p.Owner, c.now)
	if err != nil || owner.Owner.Certificate != c.owner {
		return zero, value.ErrUnavailable
	}
	c.mu.Lock()
	if c.origin != nil && (c.origin.Owner.Certificate != owner.Owner.Certificate || c.origin.Owner.EnrollmentID != owner.Owner.EnrollmentID || c.origin.Owner.ConfigurationRevision != owner.Owner.ConfigurationRevision || c.origin.Workload.Pin != owner.Workload.Pin || c.origin.Workload.Binding != owner.Workload.Binding || c.origin.Workload.Pod != owner.Workload.Pod || c.origin.Workload.ReplicaSetUID != owner.Workload.ReplicaSetUID || c.origin.Workload.WorkloadDigest != owner.Workload.WorkloadDigest) {
		c.mu.Unlock()
		return zero, value.ErrUnavailable
	}
	if c.origin == nil {
		original := owner
		c.origin = &original
	}
	c.until = identity.Earlier(c.until, owner.FreshUntil)
	until = c.until
	c.mu.Unlock()
	bounded, narrow := context.WithDeadline(call, until)
	defer narrow()
	reply, err := c.producer.observe(bounded, &c.state, c.leaf, r, p.Ordinal)
	if err != nil || bounded.Err() != nil {
		return zero, value.ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.until = identity.Earlier(c.until, ownerObservationTime(reply.FreshUntil))
	if c.closed || c.failed || c.ctx.Err() != nil || !c.now().Before(c.until) || c.producer.credentials.observationKeysCurrent(bounded, c.keys) != nil {
		return zero, value.ErrUnavailable
	}
	reply.FreshUntil = c.until.Format(time.RFC3339Nano)
	success = true
	return reply, nil
}

func (c *ConnectorObservationChannel) ObserveCluster(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	var zero value.ClusterObservationResult
	if c == nil || !r.Valid(c.now()) || r.RootID != c.pin.RootID || r.ClusterID != c.producer.pin.Profile.Binding.ClusterID {
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
	until := c.until
	c.mu.Unlock()
	if !sameConnectorObservationRequest(original, value.OwnerObservationRequest{RootID: r.RootID, ID: r.ID, Challenge: r.Challenge, RequestedAt: r.RequestedAt, NotAfter: r.NotAfter}) {
		return zero, value.ErrDenied
	}
	result, err := c.metadata.ObserveCluster(call, r.Clone())
	if err != nil || call.Err() != nil {
		return zero, value.ErrUnavailable
	}
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
	if c.closed || c.failed || c.ctx.Err() != nil || !c.now().Before(c.until) || c.producer.credentials.observationKeysCurrent(call, c.keys) != nil {
		return zero, value.ErrUnavailable
	}
	c.digest = digest
	c.until = identity.Earlier(c.until, result.Interval.FreshUntil)
	success = true
	return result, nil
}

func (c *ConnectorObservationChannel) AcceptObservationReceipt(ctx context.Context, r contracts.ClusterObservationReceipt) error {
	call, finish, err := c.enter(ctx, contracts.ClusterObservationReceiptFrame, 0)
	if err != nil {
		return err
	}
	success := false
	defer func() { finish(success) }()
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.Format != contracts.ClusterObservationExchangeFormat || r.ExchangeID != c.exchangeID || r.RequestID != c.request.ID || r.Challenge != c.request.Challenge || r.RequestDigest != ownerObservationHex(c.digest) || c.digest == (artifact.Digest{}) || c.closed || c.failed || call.Err() != nil || c.ctx.Err() != nil || !c.now().Before(c.until) || c.producer.credentials.observationKeysCurrent(call, c.keys) != nil {
		return value.ErrDenied
	}
	c.received = true
	success = true
	return nil
}

func sameConnectorObservationRequest(a, b value.OwnerObservationRequest) bool {
	return a.RootID == b.RootID && a.ID == b.ID && a.Challenge == b.Challenge && a.RequestedAt.Equal(b.RequestedAt) && a.NotAfter.Equal(b.NotAfter)
}
