package mtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextStartExecutorPin is independently installed alongside the regional
// startup projection. Hello supplies neither this image nor its configuration.
// The dynamic Pod/API epoch is additionally checked by the regional producer.
type ContextStartExecutorPin struct {
	NamespaceUID, AccountUID   string
	StartupDigest, ImageDigest artifact.Digest
}

func (p ContextStartExecutorPin) valid() bool {
	return authorization.UUID(p.NamespaceUID) && authorization.UUID(p.AccountUID) && p.StartupDigest != (artifact.Digest{}) && p.ImageDigest != (artifact.Digest{})
}
func (p ContextStartExecutorPin) matches(e value.APIContextExecutor) bool {
	return p.valid() && e.Valid() && p.NamespaceUID == e.NamespaceUID && p.AccountUID == e.AccountUID && p.StartupDigest == e.StartupDigest && p.ImageDigest == e.ImageDigest
}

// ContextStartConnectorAdmission is constructor-owned protected input, not
// registry discovery or Hello-derived policy. One exact connector per cluster.
// The profile is the installer-pinned expected profile; each exchange binds
// the registry to its own ADR-178 feed of regional source observations.
type ContextStartConnectorAdmission struct {
	Profile  value.ConnectorCredentialProfile
	Executor ContextStartExecutorPin
	Registry app.ConnectorObservationRegistry
}
type contextStartConnectorAdmission struct {
	ContextStartConnectorAdmission
	verifier *ConnectorCredentialVerifier
}
type ContextStartIngress struct {
	rootID   string
	local    *OwnerCredentials
	owners   *app.OwnerAuthenticator
	clusters map[string]contextStartConnectorAdmission
	now      func() time.Time
	// Refused, when set, receives a fixed stage name for each refusal. It carries
	// no request data and changes no result.
	Refused func(string)
}

func (s *ContextStartIngress) refuse(stage string) {
	if s != nil && s.Refused != nil {
		s.Refused(stage)
	}
}

func (s *ContextStartIngress) refuseStep(prefix string) func(string) {
	return func(step string) { s.refuse(prefix + step) }
}

// refusalClass names a refusal without request data.
func refusalClass(e error, valid, matches bool) string {
	switch {
	case errors.Is(e, value.ErrDenied):
		return "denied"
	case errors.Is(e, value.ErrUnavailable):
		return "unavailable"
	case e != nil:
		return "error"
	case !valid:
		return "expired"
	case !matches:
		return "binding"
	}
	return "other"
}

func NewContextStartIngress(rootID string, local *OwnerCredentials, owners *app.OwnerAuthenticator, inputs []ContextStartConnectorAdmission, now func() time.Time) (*ContextStartIngress, error) {
	// ADR-185: an empty catalog admits no connector, so every start is denied.
	if !authorization.UUID(rootID) || local == nil || owners == nil || owners.Now == nil || now == nil || inputs == nil || len(inputs) > 16 {
		return nil, value.ErrInvalid
	}
	c := &ContextStartIngress{rootID: rootID, local: local, owners: owners, clusters: make(map[string]contextStartConnectorAdmission, len(inputs)), now: now}
	for _, input := range inputs {
		p := input.Profile
		if !p.Valid() || p.Suspended || p.RootID != rootID || !input.Executor.valid() || input.Executor.NamespaceUID != p.Deployment.NamespaceUID || input.Executor.AccountUID != p.Deployment.AccountUID || input.Registry == nil {
			return nil, value.ErrInvalid
		}
		if _, exists := c.clusters[p.Binding.ClusterID]; exists {
			return nil, value.ErrInvalid
		}
		verifier, e := NewConnectorCredentialVerifier(p, now)
		if e != nil {
			return nil, e
		}
		input.Profile = p.Clone()
		c.clusters[p.Binding.ClusterID] = contextStartConnectorAdmission{input, verifier}
	}
	return c, nil
}

// This copies actual verified handshake evidence before any caller-owned TLS
// slices can change. Every subsequent use revalidates both root sets and SQL.
func contextStartPeerChain(s *tls.ConnectionState) ([]*x509.Certificate, error) {
	if s == nil || !s.HandshakeComplete || s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != "h2" || len(s.PeerCertificates) < 1 || len(s.PeerCertificates) > 4 || len(s.VerifiedChains) < 1 || len(s.VerifiedChains) > 8 {
		return nil, value.ErrDenied
	}
	if s.PeerCertificates[0] == nil {
		return nil, value.ErrDenied
	}
	found := false
	for _, chain := range s.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && bytes.Equal(chain[0].Raw, s.PeerCertificates[0].Raw) {
			found = true
		}
	}
	if !found {
		return nil, value.ErrDenied
	}
	out := make([]*x509.Certificate, 0, len(s.PeerCertificates))
	total := 0
	for _, cert := range s.PeerCertificates {
		if cert == nil || len(cert.Raw) < 1 || len(cert.Raw) > 16<<10 {
			return nil, value.ErrDenied
		}
		total += len(cert.Raw)
		if total > 32<<10 {
			return nil, value.ErrDenied
		}
		copied, e := x509.ParseCertificate(bytes.Clone(cert.Raw))
		if e != nil {
			return nil, value.ErrDenied
		}
		out = append(out, copied)
	}
	return out, nil
}
func contextStartDigest(s string) artifact.Digest {
	var d artifact.Digest
	if len(s) != 64 {
		return d
	}
	b, e := hex.DecodeString(s)
	if e != nil || hex.EncodeToString(b) != s {
		return d
	}
	copy(d[:], b)
	return d
}
func contextStartChannel(w contracts.APIContextChannel) value.APIContextChannel {
	h, c, e := w.Hub, w.Connector, w.Executor
	return value.APIContextChannel{RootID: w.RootID, ExchangeID: w.ExchangeID, Challenge: w.Challenge,
		Hub:       value.OwnerBinding{InstallationID: h.InstallationID, ClusterID: h.ClusterID, IssuerEpoch: h.IssuerEpoch, PodUID: h.PodUID, ProcessEpoch: h.ProcessEpoch},
		Connector: value.ConnectorProcessIdentity{Binding: value.PeerBinding{InstallationID: c.InstallationID, ClusterID: c.ClusterID, IssuerEpoch: c.IssuerEpoch, PeerID: c.PeerID, Role: value.ConnectorPeer}, PodUID: c.PodUID, ProcessEpoch: c.ProcessEpoch}, ConnectorLeaf: contextStartDigest(c.LeafDigest),
		Executor: value.APIContextExecutor{NamespaceUID: e.NamespaceUID, AccountUID: e.AccountUID, PodUID: e.PodUID, ProcessEpoch: e.ProcessEpoch, StartupDigest: contextStartDigest(e.StartupDigest), ImageDigest: contextStartDigest(e.ImageDigest)}}
}
func contextStartChannelWire(c value.APIContextChannel) contracts.APIContextChannel {
	h, p, e := c.Hub, c.Connector, c.Executor
	digest := func(d artifact.Digest) string { return hex.EncodeToString(d[:]) }
	return contracts.APIContextChannel{RootID: c.RootID, ExchangeID: c.ExchangeID, Challenge: c.Challenge,
		Hub:       contracts.APIContextOwner{InstallationID: h.InstallationID, ClusterID: h.ClusterID, IssuerEpoch: h.IssuerEpoch, PodUID: h.PodUID, ProcessEpoch: h.ProcessEpoch},
		Connector: contracts.APIContextConnector{InstallationID: p.Binding.InstallationID, ClusterID: p.Binding.ClusterID, IssuerEpoch: p.Binding.IssuerEpoch, PeerID: p.Binding.PeerID, PodUID: p.PodUID, ProcessEpoch: p.ProcessEpoch, LeafDigest: digest(c.ConnectorLeaf)},
		Executor:  contracts.APIContextExecutor{NamespaceUID: e.NamespaceUID, AccountUID: e.AccountUID, PodUID: e.PodUID, ProcessEpoch: e.ProcessEpoch, StartupDigest: digest(e.StartupDigest), ImageDigest: digest(e.ImageDigest)}}
}
func (s *ContextStartIngress) AuthenticateContextStart(ctx context.Context, state *tls.ConnectionState, hello contracts.APIContextHello, sources app.ConnectorIdentitySourceReader) (value.APIContextReceiver, app.APIContextReceiverCheck, error) {
	var zero value.APIContextReceiver
	if s == nil || ctx == nil || ctx.Err() != nil || hello.Format != contracts.APIContextExchangeFormat || sources == nil {
		s.refuse("request")
		return zero, nil, value.ErrDenied
	}
	channel := contextStartChannel(hello.Channel)
	admission, exists := s.clusters[channel.Connector.Binding.ClusterID]
	if !exists || !channel.Valid() || channel.RootID != s.rootID || channel.Connector.Binding != admission.Profile.Binding || !admission.Executor.matches(channel.Executor) {
		s.refuse("admission")
		return zero, nil, value.ErrDenied
	}
	chain, e := contextStartPeerChain(state)
	if e != nil {
		s.refuse("chain")
		return zero, nil, e
	}
	check := func(call context.Context) (value.APIContextReceiver, error) {
		return s.current(call, admission, sources, channel, chain)
	}
	receiver, e := check(ctx)
	if e != nil {
		return zero, nil, e
	}
	return receiver, check, nil
}
func (s *ContextStartIngress) current(ctx context.Context, a contextStartConnectorAdmission, sources app.ConnectorIdentitySourceReader, channel value.APIContextChannel, chain []*x509.Certificate) (value.APIContextReceiver, error) {
	var zero value.APIContextReceiver
	if ctx == nil || ctx.Err() != nil {
		s.refuse("cancelled")
		return zero, value.ErrUnavailable
	}
	started := s.now()
	call, stop := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer stop()
	until, _ := call.Deadline()
	var cancels []context.CancelFunc
	defer func() {
		for i := len(cancels) - 1; i >= 0; i-- {
			cancels[i]()
		}
	}()
	// Every narrowing is retained in the actual context used by later reads.
	narrow := func(d time.Time) {
		until = identity.Earlier(until, d)
		var cancel context.CancelFunc
		call, cancel = context.WithDeadline(call, until)
		cancels = append(cancels, cancel)
	}
	local, e := s.owners.ObserveOwnerServing(app.WithRefusalSteps(call, s.refuseStep("local/")), s.local)
	if e != nil || !local.Valid(s.now()) || local.Certificate.Binding != channel.Hub {
		s.refuse("local/" + refusalClass(e, local.Valid(s.now()), local.Certificate.Binding == channel.Hub) + app.RemainingBucket(call, s.now()))
		return zero, value.ErrDenied
	}
	narrow(local.ValidUntil)
	source, e := sources.ReadConnectorIdentitySource(call)
	if e != nil || !source.Valid(s.now()) || !source.Observation.Profile.Equal(a.Profile) {
		s.refuse("source")
		return zero, value.ErrDenied
	}
	narrow(source.Observation.FreshUntil)
	roots, _, e := OwnerTrustRoots(source.Observation.Profile.ClientIssuerRoots, s.now())
	if e != nil {
		s.refuse("roots")
		return zero, value.ErrDenied
	}
	cert, e := a.verifier.verify(chain, "client", roots)
	if e != nil || cert.Binding != channel.Connector.Binding || cert.Digest != channel.ConnectorLeaf {
		s.refuse("certificate")
		return zero, value.ErrDenied
	}
	narrow(cert.NotAfter)
	registered, e := a.Registry.ReadConnectorObservationRegistration(call, a.Profile, sources, cert)
	if e != nil || !registered.Valid(s.now()) || registered.Certificate != cert || registered.Process != channel.Connector || registered.Revision != source.Observation.Profile.Revision {
		switch {
		case e != nil || !registered.Valid(s.now()):
			s.refuse("registration/" + refusalClass(e, registered.Valid(s.now()), true))
		case registered.Certificate != cert:
			s.refuse("registration/certificate")
		case registered.Process != channel.Connector:
			s.refuse("registration/process")
		default:
			s.refuse("registration/revision")
		}
		return zero, value.ErrDenied
	}
	narrow(registered.FreshUntil)
	finalSource, e := sources.ReadConnectorIdentitySource(call)
	if e != nil || !finalSource.Valid(s.now()) || !finalSource.Observation.SameSource(source.Observation) || finalSource.Roles != source.Roles {
		s.refuse("final-source")
		return zero, value.ErrDenied
	}
	narrow(finalSource.Observation.FreshUntil)
	finalLocal, e := s.owners.ObserveOwnerServing(app.WithRefusalSteps(call, s.refuseStep("final-local/")), s.local)
	if e != nil || !finalLocal.Valid(s.now()) || !sameForwardPeer(finalLocal, local) {
		s.refuse("final-local/" + refusalClass(e, finalLocal.Valid(s.now()), sameForwardPeer(finalLocal, local)) + app.RemainingBucket(call, s.now()))
		return zero, value.ErrDenied
	}
	narrow(finalLocal.ValidUntil)
	out := value.APIContextReceiver{Channel: channel, ObservedAt: started, ValidUntil: until}
	if call.Err() != nil || !out.Valid(s.now()) || !source.Valid(s.now()) || !registered.Valid(s.now()) || !local.Valid(s.now()) {
		s.refuse("expired")
		return zero, value.ErrUnavailable
	}
	return out, nil
}
