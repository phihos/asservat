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

	// recoveryMu serializes recovery fetches so concurrent readers share one
	// hub round trip; recovery is the last observation, reused only while
	// recoveryReuseMargin of its own original validity remains.
	recoveryMu ctxMutex
	recovery   *value.RecoveryState
}

// recoveryReuseMargin is the least remaining validity a cached recovery
// observation needs to be reused instead of fetched again.
// Three seconds, like the owner route: a start's receiver/recovery bound is
// the earliest reused observation, and with two seconds a start could begin
// with under one second left for preparation headroom (installed incident
// runs 41301126897, 41299848255, 41284876053).
const recoveryReuseMargin = 3 * time.Second

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

func (r *RegionalLifecycle) run(ctx context.Context, purpose connectorlifecycle.Purpose, owner ...value.OwnerCertificate) (connectorlifecycle.HubFrame, error) {
	return r.runLocal(ctx, purpose, nil, owner...)
}

func (r *RegionalLifecycle) runLocal(ctx context.Context, purpose connectorlifecycle.Purpose, local any, owner ...value.OwnerCertificate) (connectorlifecycle.HubFrame, error) {
	var zero connectorlifecycle.HubFrame
	if r.Client == nil || r.Now == nil || ctx == nil || !r.Process.Valid() {
		return zero, value.ErrInvalid
	}
	finished := func() {}
	if r.Timing != nil {
		finished = r.Timing(purpose)
	}
	o := connectorlifecycle.Opening{Purpose: purpose, OperationID: uuid.NewString(), Process: r.Process}
	if len(owner) == 1 {
		o.Owner = &owner[0]
	}
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

// ReadContextStartOwners asks the hub for its current context-start owner set
// (ADR-172), presented by this process.
func (r *RegionalLifecycle) ReadContextStartOwners(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	frame, err := r.run(ctx, connectorlifecycle.PurposeOwnerCandidates)
	if err != nil || frame.Owners == nil || !frame.Owners.Valid(r.Now()) {
		return value.APIContextOwnerCandidates{}, unavailable(err)
	}
	return *frame.Owners, nil
}

var _ fleetapp.RecoveryReader = (*RegionalLifecycle)(nil)

// RecoveryState asks the hub for its current recovery state, presented by this
// process. It only feeds verify-only work trust; it can
// never clear or change recovery.
//
// Work verification reads it four times per source work; each read was its
// own hub conversation (native run 41206952018 refused source work at the
// second trust read). Reuse keeps the observation's original interval.
func (r *RegionalLifecycle) RecoveryState(ctx context.Context) (value.RecoveryState, error) {
	if ctx == nil {
		return value.RecoveryState{}, value.ErrUnavailable
	}
	if !r.recoveryMu.lock(ctx) {
		return value.RecoveryState{}, value.ErrUnavailable
	}
	defer r.recoveryMu.unlock()
	if c := r.recovery; c != nil && c.Valid(r.Now().Add(recoveryReuseMargin)) && c.InstallationID == r.Process.Binding.InstallationID && ctx.Err() == nil {
		return *c, nil
	}
	r.recovery = nil
	frame, err := r.run(ctx, connectorlifecycle.PurposeRecovery)
	if err != nil || frame.Recovery == nil || !frame.Recovery.Valid(r.Now()) || frame.Recovery.InstallationID != r.Process.Binding.InstallationID {
		return value.RecoveryState{}, unavailable(err)
	}
	cached := *frame.Recovery
	r.recovery = &cached
	return cached, nil
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
	frame, err := r.run(ctx, connectorlifecycle.PurposeOwnerAuthentication, certificate)
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
	_, err := r.runLocal(ctx, connectorlifecycle.PurposeAccessBindings, deliveringLocal{bindings})
	if err != nil {
		return unavailable(err)
	}
	return nil
}
