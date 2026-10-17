package mtls

import (
	"context"
	"crypto/tls"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerObservationPeer is an installed exact logical connector allowlist for
// the own-owner bootstrap purpose only. Issuer possession does not activate a
// connector, authorize workload metadata or supply a current peer source.
type OwnerObservationPeer struct {
	Binding value.PeerBinding
	Roots   [][]byte
}

type OwnerObservationIngress struct {
	pin       value.OwnerObservationPin
	server    *OwnerCredentials
	owners    *app.OwnerAuthenticator
	workloads app.OwnerObservationWorkloadReader
	peers     map[value.PeerBinding]*PeerVerifier
	now       func() time.Time
}

func NewOwnerObservationIngress(pin value.OwnerObservationPin, server *OwnerCredentials, owners *app.OwnerAuthenticator, workloads app.OwnerObservationWorkloadReader, peers []OwnerObservationPeer, now func() time.Time) (*OwnerObservationIngress, error) {
	if !pin.Valid() || server == nil || server.usage != "server" || !server.verifier.matchesPool(pin.Pool) || owners == nil || owners.Now == nil || workloads == nil || len(peers) < 1 || len(peers) > 16 || now == nil {
		return nil, value.ErrInvalid
	}
	s := &OwnerObservationIngress{pin: pin, server: server, owners: owners, workloads: workloads, peers: make(map[value.PeerBinding]*PeerVerifier, len(peers)), now: now}
	for _, p := range peers {
		if !p.Binding.Valid() || p.Binding.Role != value.ConnectorPeer || p.Binding.InstallationID != pin.Pool.InstallationID || p.Binding.IssuerEpoch != pin.Pool.IssuerEpoch || s.peers[p.Binding] != nil {
			return nil, value.ErrInvalid
		}
		roots, _, e := OwnerTrustRoots(p.Roots, now())
		if e != nil {
			return nil, e
		}
		v, e := NewPeerVerifier(roots, p.Binding.InstallationID, value.ConnectorPeer, now)
		if e != nil {
			return nil, e
		}
		s.peers[p.Binding] = v
	}
	return s, nil
}

func (s *OwnerObservationIngress) peer(state *tls.ConnectionState) (value.PeerCertificate, error) {
	var zero value.PeerCertificate
	if s == nil || state == nil || state.DidResume || !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" || len(state.PeerCertificates) < 1 || state.PeerCertificates[0] == nil || len(state.PeerCertificates[0].URIs) != 1 {
		return zero, value.ErrDenied
	}
	common, e := OwnerBootstrapServerName(s.pin.Pool)
	if e != nil || state.ServerName != common {
		return zero, value.ErrDenied
	}
	// Parsing chooses one already installed verifier. The raw URI supplies no
	// root, issuer acceptance, new allowlist entry or authority.
	binding, e := parsePeerURI(state.PeerCertificates[0].URIs[0], s.pin.Pool.InstallationID, value.ConnectorPeer)
	if e != nil {
		return zero, value.ErrDenied
	}
	v := s.peers[binding]
	if v == nil {
		return zero, value.ErrDenied
	}
	out, e := v.Verify(state)
	if e != nil || out.Binding != binding {
		return zero, value.ErrDenied
	}
	return out, nil
}

func (s *OwnerObservationIngress) ObserveOwnerPeer(ctx context.Context, state *tls.ConnectionState, input contracts.OwnerObservationRequest) (contracts.OwnerObservationReply, error) {
	var zero contracts.OwnerObservationReply
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	started := s.now()
	r, e := ownerObservationRequest(input, started)
	if e != nil || r.RootID != s.pin.RootID {
		return zero, value.ErrDenied
	}
	peer, e := s.peer(state)
	if e != nil {
		return zero, e
	}
	connection, e := ownerObservationConnection(state, r)
	if e != nil {
		return zero, e
	}
	until := identity.Earlier(started.Add(5*time.Second), identity.Earlier(r.NotAfter, peer.NotAfter))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	first, e := s.owners.ObserveOwnerServing(call, s.server)
	if e != nil || !first.Valid(s.now()) || first.Pool != s.pin.Pool || first.ConfigurationRevision.UID != s.pin.SourceUID || first.ProtectionDigest != s.pin.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, first.ValidUntil)
	bounded, stop := context.WithDeadline(call, until)
	defer stop()
	workload, e := s.workloads.ObserveOwnerWorkload(bounded, first.Certificate.Binding, first.Pod)
	if e != nil || !workload.Valid(s.now()) || workload.Pin != s.pin || workload.Binding != first.Certificate.Binding || workload.Pod != first.Pod || workload.ReplicaSetUID != first.ReplicaSetUID {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, workload.FreshUntil)
	finalCall, end := context.WithDeadline(bounded, until)
	defer end()
	last, e := s.owners.ObserveOwnerServing(finalCall, s.server)
	if e != nil || !last.Valid(s.now()) || last.Certificate != first.Certificate || last.EnrollmentID != first.EnrollmentID || last.Pool != first.Pool || last.Pod != first.Pod || last.ReplicaSetUID != first.ReplicaSetUID || last.ConfigurationRevision != first.ConfigurationRevision || last.ProtectionDigest != first.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	finalPeer, e := s.peer(state)
	if e != nil || finalPeer != peer {
		return zero, value.ErrDenied
	}
	until = identity.Earlier(until, last.ValidUntil)
	observed := started
	for _, t := range []time.Time{first.VerifiedAt, last.VerifiedAt, workload.ObservedAt} {
		if observed.Before(t) {
			observed = t
		}
	}
	// Keep the first authority interval even though the final independent read
	// may be newer. No successful read can restore time spent in this request.
	out := value.OwnerObservation{Request: r, ConnectionBinding: connection, Connector: peer, Owner: first, Workload: workload, ObservedAt: observed, FreshUntil: until}
	if finalCall.Err() != nil || !out.Valid(s.now()) {
		return zero, value.ErrUnavailable
	}
	return ownerObservationReplyWire(out)
}

// This is invoked only by the concrete client over the same actual connection
// and its immutable pre-handshake candidate set. It does not re-discover a new
// owner after the load balancer selected one, and never performs source writes.
func checkOwnerObservation(ctx context.Context, state *tls.ConnectionState, verifier *OwnerPeerVerifier, registry app.OwnerCertificateRegistry, candidates value.APIContextOwnerCandidates, pin value.OwnerObservationPin, request value.OwnerObservationRequest, connector value.PeerCertificate, wire contracts.OwnerObservationReply, now func() time.Time) (value.OwnerObservation, error) {
	var zero value.OwnerObservation
	if ctx == nil || ctx.Err() != nil || verifier == nil || registry == nil || now == nil || !pin.Valid() || !request.Valid(now()) || !connector.Valid(now()) || candidates.Pool != pin.Pool || !candidates.Valid(now()) {
		return zero, value.ErrUnavailable
	}
	owner, e := verifier.VerifyBootstrapServer(state, candidates)
	if e != nil {
		return zero, e
	}
	connection, e := ownerObservationConnection(state, request)
	if e != nil {
		return zero, e
	}
	out, e := parseOwnerObservationReply(wire, pin, connector, owner, now())
	if e != nil || !out.Matches(request, pin, connection, connector, owner, now()) {
		return zero, value.ErrDenied
	}
	until := identity.Earlier(request.NotAfter, identity.Earlier(candidates.ValidUntil, out.FreshUntil))
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	registered, e := registry.ReadOwnerRegistration(call, owner)
	if e != nil || !registered.Valid(now()) || registered.Certificate != owner || registered.Enrollment.ID != out.Owner.EnrollmentID || registered.Enrollment.Pool != pin.Pool || registered.Enrollment.SourceUID != pin.SourceUID || registered.Enrollment.Pod != out.Owner.Pod || registered.Enrollment.ReplicaSetUID != out.Owner.ReplicaSetUID || registered.Configuration.Configuration.Revision != out.Owner.ConfigurationRevision {
		return zero, value.ErrUnavailable
	}
	current, e := verifier.currentVerifier(registered.Configuration)
	if e != nil {
		return zero, e
	}
	checked, e := current.VerifyBootstrapServer(state, candidates)
	if e != nil || checked != owner || call.Err() != nil || !out.Matches(request, pin, connection, connector, owner, now()) || !candidates.Valid(now()) || !registered.Valid(now()) {
		return zero, value.ErrUnavailable
	}
	out.FreshUntil = identity.Earlier(until, registered.FreshUntil)
	if !out.Valid(now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
