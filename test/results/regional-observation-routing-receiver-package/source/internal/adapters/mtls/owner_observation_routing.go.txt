package mtls

import (
	"context"
	"crypto/tls"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerObservationRoutingPeers is constructed only by the original installed
// backend composition. It admits same-pool owner delegation, not human, worker
// enrollment, capture or regional connector credentials. No incoming value can
// select its root, source, pool, template, verifier or authority reader.
type OwnerObservationRoutingPeers struct {
	pin       value.OwnerObservationPin
	server    *OwnerCredentials
	owners    *app.OwnerAuthenticator
	workloads app.OwnerObservationWorkloadReader
	now       func() time.Time
}

func NewOwnerObservationRoutingPeers(pin value.OwnerObservationPin, server *OwnerCredentials, owners *app.OwnerAuthenticator, workloads app.OwnerObservationWorkloadReader, now func() time.Time) (*OwnerObservationRoutingPeers, error) {
	if !pin.Valid() || pin.Pool.NativeCandidateLimit == 0 || server == nil || server.usage != "server" || !server.verifier.matchesPool(pin.Pool) || owners == nil || owners.Registry == nil || owners.Routes == nil || owners.Protection == nil || owners.Now == nil || workloads == nil || now == nil {
		return nil, value.ErrInvalid
	}
	return &OwnerObservationRoutingPeers{pin, server, owners, workloads, now}, nil
}

// CheckObservationRouting preserves the supplied original query/caller bound.
// The handler separately binds locator/common-SNI versus claim/exact-SNI and
// matching HTTP authority. This adapter permits only those two original names;
// changing Host cannot select another pool or replace actual TLS identity.
func (s *OwnerObservationRoutingPeers) CheckObservationRouting(ctx context.Context, state *tls.ConnectionState, q value.ClusterObservationLocatorQuery) (value.ClusterObservationRoutingPeers, error) {
	var zero value.ClusterObservationRoutingPeers
	if s == nil || ctx == nil || ctx.Err() != nil || !q.Valid(s.now()) || q.RootID != s.pin.RootID || state == nil || state.DidResume || !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" {
		return zero, value.ErrDenied
	}
	common, ce := OwnerBootstrapServerName(s.pin.Pool)
	exact, ee := OwnerServerName(s.server.binding)
	if ce != nil || ee != nil || state.ServerName != common && state.ServerName != exact {
		return zero, value.ErrDenied
	}
	peer, err := NewOwnerClientConnection(s.server.verifier, state)
	if err != nil {
		return zero, err
	}
	client, err := peer.OwnerCertificate()
	if err != nil {
		return zero, err
	}
	until := identity.Earlier(q.NotAfter, client.NotAfter)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	sender, err := s.owners.AuthenticateOwner(call, peer)
	if err != nil || !sender.Valid(s.now()) || sender.Pool != s.pin.Pool || sender.ConfigurationRevision.UID != s.pin.SourceUID || sender.ProtectionDigest != s.pin.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, sender.ValidUntil)
	peerCall, stopPeer := context.WithDeadline(call, until)
	defer stopPeer()
	senderWorkload, err := s.workloads.ObserveOwnerWorkload(peerCall, sender.Certificate.Binding, sender.Pod)
	if err != nil || !senderWorkload.Valid(s.now()) || senderWorkload.Pin != s.pin {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, senderWorkload.FreshUntil)
	localCall, stopLocal := context.WithDeadline(peerCall, until)
	defer stopLocal()
	holder, err := s.owners.ObserveOwnerServing(localCall, s.server)
	if err != nil || !holder.Valid(s.now()) || holder.Pool != s.pin.Pool || holder.ConfigurationRevision != sender.ConfigurationRevision || holder.ProtectionDigest != s.pin.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, holder.ValidUntil)
	workCall, stopWork := context.WithDeadline(localCall, until)
	defer stopWork()
	holderWorkload, err := s.workloads.ObserveOwnerWorkload(workCall, holder.Certificate.Binding, holder.Pod)
	if err != nil || !holderWorkload.Valid(s.now()) || holderWorkload.Pin != s.pin {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, holderWorkload.FreshUntil)
	// Current private-key closure/renewal and actual peer-certificate expiry
	// veto delivery after blocking native work. These checks do not mint proof.
	finalClient, err := peer.OwnerCertificate()
	if err != nil || finalClient != sender.Certificate {
		return zero, value.ErrDenied
	}
	finalServer, err := s.server.ServingCertificate()
	if err != nil || finalServer != holder.Certificate {
		return zero, value.ErrDenied
	}
	start := q.RequestedAt
	for _, observed := range []time.Time{sender.VerifiedAt, senderWorkload.ObservedAt, holder.VerifiedAt, holderWorkload.ObservedAt} {
		if start.Before(observed) {
			start = observed
		}
	}
	out := value.ClusterObservationRoutingPeers{Query: q, Pin: s.pin, Sender: sender, Holder: holder, SenderWorkload: senderWorkload, HolderWorkload: holderWorkload, Interval: value.ClusterObservationInterval{ObservedAt: start, FreshUntil: until}}
	if workCall.Err() != nil || !out.Valid(s.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
