package mtls

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// The sole implementation is the retained closed observation stream. Each call
// writes one new numbered probe on that stream and consumes its exact reply.
// There is no generic RPC method, endpoint selection or cached-source fallback.
type connectorObservationProofExchange interface {
	ReadConnectorObservation(context.Context, int) (contracts.ConnectorObservationReply, error)
}

// RemoteConnectorObservationSource supplies the existing exact SQL49 registry's
// pre/post reads. Every invocation performs new remote native observation. Its
// four attempts are spent before I/O; any uncertain call permanently fails this
// source and cannot be replayed. A new stream never inherits its request.
type RemoteConnectorObservationSource struct {
	pin                  value.ConnectorObservationPin
	request              value.OwnerObservationRequest
	state                tls.ConnectionState
	channel              artifact.Digest
	leaf                 value.ConnectorCredentialCertificate
	verifier             *ConnectorCredentialVerifier
	exchange             connectorObservationProofExchange
	now                  func() time.Time
	ctx                  context.Context
	cancel               context.CancelFunc
	mu                   sync.Mutex
	busy, failed, closed bool
	ordinal              int
	until                time.Time
	first, last          *value.ConnectorObservation
	joined               sync.WaitGroup
}

var _ app.ConnectorIdentitySourceReader = (*RemoteConnectorObservationSource)(nil)

func NewRemoteConnectorObservationSource(ctx context.Context, pin value.ConnectorObservationPin, owner value.OwnerObservationPin, request value.OwnerObservationRequest, state *tls.ConnectionState, exchange connectorObservationProofExchange, now func() time.Time) (*RemoteConnectorObservationSource, error) {
	if ctx == nil || ctx.Err() != nil || !pin.Valid() || !owner.Valid() || now == nil || !request.Valid(now()) || request.RootID != pin.Profile.RootID || request.RootID != owner.RootID || pin.Profile.Binding.InstallationID != owner.Pool.InstallationID || exchange == nil {
		return nil, value.ErrInvalid
	}
	common, e := OwnerBootstrapServerName(owner.Pool)
	if e != nil || state == nil || state.ServerName != common {
		return nil, value.ErrDenied
	}
	channel, e := ownerObservationConnection(state, request)
	if e != nil {
		return nil, e
	}
	snapshot, e := snapshotOwnerTLS(state)
	if e != nil {
		return nil, e
	}
	verifier, e := NewConnectorCredentialVerifier(pin.Profile, now)
	if e != nil {
		return nil, e
	}
	leaf, e := verifier.verify(snapshot.PeerCertificates, "client", verifier.clientRoots)
	if e != nil || leaf.Binding != pin.Profile.Binding {
		return nil, value.ErrDenied
	}
	until := identity.Earlier(request.NotAfter, identity.Earlier(now().Add(5*time.Second), leaf.NotAfter))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	return &RemoteConnectorObservationSource{pin: pin.Clone(), request: request, state: snapshot, channel: channel, leaf: leaf, verifier: verifier, exchange: exchange, now: now, ctx: call, cancel: cancel, until: until}, nil
}

func (s *RemoteConnectorObservationSource) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	// The stream must honor cancellation and join its actual read/write owner.
	// Returning from a local cancellation is never a remote completion receipt.
	s.joined.Wait()
}

func (s *RemoteConnectorObservationSource) ReadConnectorIdentitySource(ctx context.Context) (value.ConnectorIdentitySource, error) {
	var zero value.ConnectorIdentitySource
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	s.mu.Lock()
	if s.closed || s.failed || s.busy || s.ctx.Err() != nil || s.ordinal >= value.ConnectorObservationMaximumChecks || !s.now().Before(s.until) {
		s.mu.Unlock()
		return zero, value.ErrUnavailable
	}
	s.busy = true
	s.ordinal++
	ordinal, until := s.ordinal, s.until
	s.joined.Add(1)
	s.mu.Unlock()
	success := false
	defer func() {
		s.mu.Lock()
		s.busy = false
		if !success {
			s.failed = true
		}
		s.mu.Unlock()
		s.joined.Done()
	}()
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	done := make(chan struct{})
	stop := context.AfterFunc(s.ctx, func() { cancel(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	before, e := s.verifier.verify(s.state.PeerCertificates, "client", s.verifier.clientRoots)
	if e != nil || before != s.leaf {
		return zero, value.ErrUnavailable
	}
	wire, e := s.exchange.ReadConnectorObservation(call, ordinal)
	if e != nil {
		return zero, value.ErrUnavailable
	}
	observed, e := parseConnectorObservationReply(wire, s.pin, s.leaf, s.request, ordinal, s.channel, s.now())
	if e != nil {
		return zero, value.ErrUnavailable
	}
	// The independently installed compatible profile fixes both issuer sets.
	// The RPC's current accepted source/recovery checks remain mandatory; this
	// transport value cannot accept a revision or activate the peer itself.
	after, e := s.verifier.verify(s.state.PeerCertificates, "client", s.verifier.clientRoots)
	if e != nil || after != before || call.Err() != nil || s.ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.failed || !s.now().Before(s.until) {
		return zero, value.ErrUnavailable
	}
	if first := s.first; first != nil {
		if first.Certificate != observed.Certificate || first.Workload.Process != observed.Workload.Process || first.Workload.Pod != observed.Workload.Pod || first.Workload.ReplicaSetUID != observed.Workload.ReplicaSetUID || first.Workload.WorkloadDigest != observed.Workload.WorkloadDigest || !first.Source.Observation.SameSource(observed.Source.Observation) || first.Source.Roles != observed.Source.Roles {
			return zero, value.ErrUnavailable
		}
	}
	s.until = identity.Earlier(s.until, observed.FreshUntil)
	observed.FreshUntil = s.until
	observed.Source.Observation.FreshUntil = identity.Earlier(observed.Source.Observation.FreshUntil, s.until)
	if !observed.Matches(s.pin, s.now()) {
		return zero, value.ErrUnavailable
	}
	if s.first == nil {
		first := observed
		first.Source.Observation.Profile = first.Source.Observation.Profile.Clone()
		s.first = &first
	}
	last := observed
	last.Source.Observation.Profile = last.Source.Observation.Profile.Clone()
	s.last = &last
	out := observed.Source
	out.Observation.Profile = out.Observation.Profile.Clone()
	success = true
	return out, nil
}

// MatchRegistration is called after the existing RPC completed both fresh
// source reads. It adds exact process/template binding to the RPC's activated
// leaf/source check; neither a source reply alone nor this comparison is a grant.
func (s *RemoteConnectorObservationSource) MatchRegistration(r app.ConnectorLeafRegistration) (time.Time, error) {
	if s == nil {
		return time.Time{}, value.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.last
	if s.closed || s.failed || s.busy || s.ctx.Err() != nil || s.ordinal != 2 && s.ordinal != 4 || o == nil || !s.now().Before(s.until) || !o.Matches(s.pin, s.now()) || !r.Valid(s.now()) || r.Certificate != o.Certificate || r.Process != o.Workload.Process || r.Revision != o.Source.Observation.Profile.Revision {
		return time.Time{}, value.ErrUnavailable
	}
	s.until = identity.Earlier(s.until, r.FreshUntil)
	if !s.now().Before(s.until) {
		return time.Time{}, value.ErrUnavailable
	}
	return s.until, nil
}
