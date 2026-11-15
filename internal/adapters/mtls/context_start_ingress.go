package mtls

import (
	"context"
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

// ContextStartIngress admits a connector's context-start exchange. The
// connector authenticated with its ServiceAccount token (ADR-334); the hello
// must name the cluster and peer that token was attributed to. The executor's
// startup and image digests in Hello are provenance only: a connector of
// another release is admitted (ADR-333 version skew).
type ContextStartIngress struct {
	rootID string
	local  *OwnerCredentials
	owners *app.OwnerAuthenticator
	now    func() time.Time
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

func NewContextStartIngress(rootID string, local *OwnerCredentials, owners *app.OwnerAuthenticator, now func() time.Time) (*ContextStartIngress, error) {
	if !authorization.UUID(rootID) || local == nil || owners == nil || owners.Now == nil || now == nil {
		return nil, value.ErrInvalid
	}
	return &ContextStartIngress{rootID: rootID, local: local, owners: owners, now: now}, nil
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
		Connector: value.ConnectorProcessIdentity{Binding: value.PeerBinding{InstallationID: c.InstallationID, ClusterID: c.ClusterID, IssuerEpoch: c.IssuerEpoch, PeerID: c.PeerID, Role: value.ConnectorPeer}, PodUID: c.PodUID, ProcessEpoch: c.ProcessEpoch},
		Executor:  value.APIContextExecutor{NamespaceUID: e.NamespaceUID, AccountUID: e.AccountUID, PodUID: e.PodUID, ProcessEpoch: e.ProcessEpoch, StartupDigest: contextStartDigest(e.StartupDigest), ImageDigest: contextStartDigest(e.ImageDigest)}}
}
func contextStartChannelWire(c value.APIContextChannel) contracts.APIContextChannel {
	h, p, e := c.Hub, c.Connector, c.Executor
	digest := func(d artifact.Digest) string { return hex.EncodeToString(d[:]) }
	return contracts.APIContextChannel{RootID: c.RootID, ExchangeID: c.ExchangeID, Challenge: c.Challenge,
		Hub:       contracts.APIContextOwner{InstallationID: h.InstallationID, ClusterID: h.ClusterID, IssuerEpoch: h.IssuerEpoch, PodUID: h.PodUID, ProcessEpoch: h.ProcessEpoch},
		Connector: contracts.APIContextConnector{InstallationID: p.Binding.InstallationID, ClusterID: p.Binding.ClusterID, IssuerEpoch: p.Binding.IssuerEpoch, PeerID: p.Binding.PeerID, PodUID: p.PodUID, ProcessEpoch: p.ProcessEpoch},
		Executor:  contracts.APIContextExecutor{NamespaceUID: e.NamespaceUID, AccountUID: e.AccountUID, PodUID: e.PodUID, ProcessEpoch: e.ProcessEpoch, StartupDigest: digest(e.StartupDigest), ImageDigest: digest(e.ImageDigest)}}
}

// AuthenticateContextStart binds the hello to the token's cluster. The
// returned check repeats the hub's own serving check and never outlives the
// token.
func (s *ContextStartIngress) AuthenticateContextStart(ctx context.Context, hello contracts.APIContextHello, presented value.ConnectorCluster, tokenUntil time.Time) (value.APIContextReceiver, app.APIContextReceiverCheck, error) {
	var zero value.APIContextReceiver
	if s == nil || ctx == nil || ctx.Err() != nil || hello.Format != contracts.APIContextExchangeFormat {
		s.refuse("request")
		return zero, nil, value.ErrDenied
	}
	channel := contextStartChannel(hello.Channel)
	b := channel.Connector.Binding
	if !channel.Valid() || channel.RootID != s.rootID || presented.RootID != s.rootID || b.ClusterID != presented.ClusterID || b.PeerID != presented.PeerID || b.InstallationID != presented.InstallationID {
		s.refuse("admission")
		return zero, nil, value.ErrDenied
	}
	check := func(call context.Context) (value.APIContextReceiver, error) {
		return s.current(call, channel, tokenUntil)
	}
	receiver, e := check(ctx)
	if e != nil {
		return zero, nil, e
	}
	return receiver, check, nil
}

func (s *ContextStartIngress) current(ctx context.Context, channel value.APIContextChannel, tokenUntil time.Time) (value.APIContextReceiver, error) {
	var zero value.APIContextReceiver
	if ctx == nil || ctx.Err() != nil {
		s.refuse("cancelled")
		return zero, value.ErrUnavailable
	}
	started := s.now()
	if !started.Before(tokenUntil) {
		s.refuse("token-expired")
		return zero, value.ErrDenied
	}
	call, stop := context.WithDeadline(ctx, identity.Earlier(started.Add(5*time.Second), tokenUntil))
	defer stop()
	local, e := s.owners.ObserveOwnerServing(app.WithRefusalSteps(call, s.refuseStep("local/")), s.local)
	if e != nil || !local.Valid(s.now()) || local.Certificate.Binding != channel.Hub {
		s.refuse("local/" + refusalClass(e, local.Valid(s.now()), local.Certificate.Binding == channel.Hub) + app.RemainingBucket(call, s.now()))
		return zero, value.ErrDenied
	}
	out := value.APIContextReceiver{Channel: channel, Window: identity.Check(started, identity.Recheck).Narrow(local.ValidUntil, tokenUntil)}
	if call.Err() != nil || !out.Valid(s.now()) {
		s.refuse("expired")
		return zero, value.ErrUnavailable
	}
	return out, nil
}
