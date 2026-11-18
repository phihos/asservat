package bootstrap

import (
	"context"
	"errors"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
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

func (r *RegionalLifecycle) run(ctx context.Context, purpose connectorlifecycle.Purpose, owner *value.OwnerCertificate, local any) (connectorlifecycle.HubFrame, error) {
	var zero connectorlifecycle.HubFrame
	if r.Client == nil || r.Now == nil || ctx == nil || !r.Process.Valid() {
		return zero, value.ErrInvalid
	}
	finished := func() {}
	if r.Timing != nil {
		finished = r.Timing(purpose)
	}
	o := connectorlifecycle.Opening{Purpose: purpose, Protocol: contracts.ConnectorProtocolMajor, OperationID: uuid.NewString(), Process: r.Process, Owner: owner}
	frame, err := r.Client.Run(ctx, o, local)
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
	frame, err := r.run(ctx, connectorlifecycle.PurposeOwnerAuthentication, &certificate, nil)
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

// AccessBindingReader is the connector's own AccessBinding LIST (ADR-329).
type AccessBindingReader interface {
	AccessBindingDelivery(context.Context) (contracts.AccessBindingDelivery, error)
}

// deliveringLocal answers the hub's delivery request of one conversation
// with a LIST taken after the hub verified the presentation.
type deliveringLocal struct {
	bindings AccessBindingReader
}

func (d deliveringLocal) ReadAccessBindings(ctx context.Context) (contracts.AccessBindingDelivery, error) {
	out, err := d.bindings.AccessBindingDelivery(ctx)
	regionalLocalFailed("access bindings", err)
	return out, err
}

// DeliverAccessBindings sends this cluster's complete AccessBinding LIST to
// the hub in one lifecycle conversation, presented by this process
// (ADR-329). The hub attributes it to the cluster credential's cluster.
func (r *RegionalLifecycle) DeliverAccessBindings(ctx context.Context, bindings AccessBindingReader) error {
	if bindings == nil || ctx == nil {
		return value.ErrUnavailable
	}
	_, err := r.run(ctx, connectorlifecycle.PurposeAccessBindings, nil, deliveringLocal{bindings})
	if err != nil {
		return unavailable(err)
	}
	return nil
}
