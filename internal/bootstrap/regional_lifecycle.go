package bootstrap

import (
	"context"
	"errors"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	"github.com/google/uuid"
)

// RegionalLifecycle is the connector's side of its finite hub conversations
// (ADR-169): each call is one conversation authenticated by the connector's
// ServiceAccount token (ADR-334) and presented by this process. The hub keeps
// every effect; this side never holds SQL, signing or audit authority.
type RegionalLifecycle struct {
	Client  *connectorlifecycle.Client
	Process value.ConnectorProcessIdentity
	RootID  string
	Now     func() time.Time
	// Timing, when set, is called as each conversation starts and returns
	// the func its success calls (ADR-197 spike diagnostics; never content).
	Timing func(connectorlifecycle.Purpose) func()
}

// Closed causes kept alongside ErrUnavailable for operator diagnostics only.
var (
	errRegionalCredential = errors.New("cluster credential unavailable")
	errRegionalChannel    = errors.New("hub channel unavailable")
	errRegionalRefused    = errors.New("hub refused the operation")
)

// unavailable keeps the closed cause while every caller still sees
// ErrUnavailable.
func unavailable(cause error) error {
	if cause == nil || !(errors.Is(cause, errRegionalCredential) || errors.Is(cause, errRegionalChannel) || errors.Is(cause, errRegionalRefused)) {
		return value.ErrUnavailable
	}
	return errors.Join(value.ErrUnavailable, cause)
}

func (r *RegionalLifecycle) run(ctx context.Context, opening connectorlifecycle.Opening, delivery *contracts.AccessBindingDelivery) (connectorlifecycle.HubFrame, error) {
	var zero connectorlifecycle.HubFrame
	if r.Client == nil || r.Now == nil || ctx == nil || !r.Process.Valid() {
		return zero, value.ErrInvalid
	}
	finished := func() {}
	if r.Timing != nil {
		finished = r.Timing(opening.Purpose)
	}
	opening.Protocol, opening.OperationID, opening.Process = contracts.ConnectorProtocolMajor, uuid.NewString(), r.Process
	frame, err := r.Client.Run(ctx, opening, delivery)
	if err != nil {
		return zero, errRegionalChannel
	}
	if frame.Kind != "result" {
		return zero, errRegionalRefused
	}
	finished()
	return frame, nil
}

// AuthenticateOwner authenticates the owner of an actual TLS session: the hub
// supplies its registration, protection and route facts for the observed
// certificate, and this side verifies its own session against the returned
// configuration. The hub's answer alone authenticates nothing.
func (r *RegionalLifecycle) AuthenticateOwner(ctx context.Context, connection fleetapp.OwnerPeerConnection) (value.AuthenticatedOwner, error) {
	var zero value.AuthenticatedOwner
	if connection == nil || ctx == nil {
		return zero, value.ErrUnavailable
	}
	certificate, err := connection.OwnerCertificate()
	if err != nil || certificate.Usage != "server" || !certificate.Valid(r.Now()) {
		return zero, value.ErrDenied
	}
	frame, err := r.run(ctx, connectorlifecycle.Opening{Purpose: connectorlifecycle.PurposeOwnerAuthentication, Owner: &certificate}, nil)
	if err != nil || frame.Owner == nil {
		return zero, unavailable(err)
	}
	answer := *frame.Owner
	if answer.Owner.Certificate != certificate || !answer.Configuration.Valid(r.Now()) || answer.Owner.ConfigurationRevision != answer.Configuration.Configuration.Revision {
		return zero, value.ErrDenied
	}
	current, err := connection.VerifyCurrentOwner(answer.Configuration)
	if err != nil || current != certificate {
		return zero, value.ErrDenied
	}
	out := answer.Owner
	out.ValidUntil = identity.Earlier(out.ValidUntil, answer.Configuration.FreshUntil)
	if ctx.Err() != nil || !out.Valid(r.Now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}

func (r *RegionalLifecycle) bindingRevision(ctx context.Context) (string, error) {
	return r.exchangeBindings(ctx, connectorlifecycle.Opening{Purpose: connectorlifecycle.PurposeBindingRevision}, nil)
}

func (r *RegionalLifecycle) deliverAccessBindings(ctx context.Context, revision string, delivery contracts.AccessBindingDelivery) (string, error) {
	return r.exchangeBindings(ctx, connectorlifecycle.Opening{Purpose: connectorlifecycle.PurposeAccessBindings, BindingRevision: revision}, &delivery)
}

func (r *RegionalLifecycle) exchangeBindings(ctx context.Context, opening connectorlifecycle.Opening, delivery *contracts.AccessBindingDelivery) (string, error) {
	frame, err := r.run(ctx, opening, delivery)
	if err != nil || !authorization.UUID(frame.BindingRevision) {
		return "", unavailable(err)
	}
	return frame.BindingRevision, nil
}
