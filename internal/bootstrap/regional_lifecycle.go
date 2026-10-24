package bootstrap

import (
	"context"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/clustercredential"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	"github.com/google/uuid"
)

// RegionalLifecycle implements the connector process credential and leaf
// registry ports for an outbound regional process (ADR-168/169). Each call is
// one channel conversation: the cluster credential presents possession over
// that connection, and the in-cluster readers answer every ADR-153 phase and
// source read. The hub keeps every effect; this side never holds SQL, signing
// or audit authority.
type RegionalLifecycle struct {
	Client     *connectorlifecycle.Client
	Local      connectorlifecycle.Local
	Credential fleetapp.ClusterCredentialRotator
	Now        func() time.Time
	// Timing, when set, is called as each conversation starts and returns
	// the func its success calls (ADR-197 spike diagnostics; never content).
	Timing func(value.ConnectorLifecyclePurpose) func()

	mu      sync.Mutex
	issued  []regionalLeaf // the latest leaves and the process request they belong to
	current *value.ConnectorProcessRequest
}

type regionalLeaf struct {
	certificate value.ConnectorCredentialCertificate
	request     value.ConnectorProcessRequest
}

// ponytail: one process holds at most two current plus two pending leaves.
const regionalLeaves = 4

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

var (
	_ mtls.ConnectorProcessAdmitter  = (*RegionalLifecycle)(nil)
	_ mtls.ConnectorProcessIssuer    = (*RegionalLifecycle)(nil)
	_ fleetapp.ConnectorLeafRegistry = (*RegionalLifecycle)(nil)
)

func (r *RegionalLifecycle) Enroll(ctx context.Context, id string, request value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	frame, err := r.run(ctx, value.ConnectorLifecycleEnroll, value.ClusterAdmission, id, request, nil)
	if err != nil || frame.Process == nil {
		return value.ConnectorCredentialProcess{}, unavailable(err)
	}
	r.mu.Lock()
	admitted := request
	r.current = &admitted // the admitted process presents owner reads (ADR-172)
	r.mu.Unlock()
	return *frame.Process, nil
}

func (r *RegionalLifecycle) IssueProcess(ctx context.Context, id, usage string, request value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error) {
	purpose := value.ConnectorLifecycleClient
	if usage == "server" {
		purpose = value.ConnectorLifecycleServer
	} else if usage != "client" {
		return value.IssuedConnectorCredential{}, value.ErrInvalid
	}
	frame, err := r.run(ctx, purpose, value.ClusterRenewal, id, request, nil)
	if err != nil || frame.Credential == nil {
		return value.IssuedConnectorCredential{}, unavailable(err)
	}
	r.mu.Lock()
	r.issued = append(r.issued, regionalLeaf{frame.Credential.Certificate, request})
	if len(r.issued) > regionalLeaves {
		r.issued = r.issued[len(r.issued)-regionalLeaves:]
	}
	r.mu.Unlock()
	return *frame.Credential, nil
}

// ConnectorLeafRegistration asks the hub for the current registration of a
// leaf this adapter received, presented by the process that requested it. An
// unknown leaf is never looked up: it has no process to present.
func (r *RegionalLifecycle) ConnectorLeafRegistration(ctx context.Context, c value.ConnectorCredentialCertificate) (fleetapp.ConnectorLeafRegistration, error) {
	return r.connectorLeafRegistration(ctx, c, r.Local)
}

func (r *RegionalLifecycle) connectorLeafRegistration(ctx context.Context, c value.ConnectorCredentialCertificate, local connectorlifecycle.Local) (fleetapp.ConnectorLeafRegistration, error) {
	var request *value.ConnectorProcessRequest
	r.mu.Lock()
	for i := range r.issued {
		if r.issued[i].certificate == c {
			request = &r.issued[i].request
		}
	}
	r.mu.Unlock()
	if request == nil {
		return fleetapp.ConnectorLeafRegistration{}, value.ErrUnavailable
	}
	frame, err := r.runLocal(ctx, connectorlifecycle.PurposeRegistration, value.ClusterRenewal, uuid.NewString(), *request, &c, local)
	if err != nil || frame.Registration == nil || frame.Registration.Certificate != c || frame.Registration.Process != request.Process {
		return fleetapp.ConnectorLeafRegistration{}, unavailable(err)
	}
	return *frame.Registration, nil
}

func (r *RegionalLifecycle) run(ctx context.Context, purpose value.ConnectorLifecyclePurpose, operation, id string, request value.ConnectorProcessRequest, leaf *value.ConnectorCredentialCertificate, owner ...value.OwnerCertificate) (connectorlifecycle.HubFrame, error) {
	return r.runLocal(ctx, purpose, operation, id, request, leaf, r.Local, owner...)
}

func (r *RegionalLifecycle) runLocal(ctx context.Context, purpose value.ConnectorLifecyclePurpose, operation, id string, request value.ConnectorProcessRequest, leaf *value.ConnectorCredentialCertificate, local connectorlifecycle.Local, owner ...value.OwnerCertificate) (connectorlifecycle.HubFrame, error) {
	var zero connectorlifecycle.HubFrame
	if r.Client == nil || local == nil || r.Now == nil || ctx == nil || !request.Valid() {
		return zero, value.ErrInvalid
	}
	client, err := mtls.EnrollmentKey(request.ClientCSRDER)
	if err != nil {
		return zero, value.ErrInvalid
	}
	server, err := mtls.EnrollmentKey(request.ServerCSRDER)
	if err != nil {
		return zero, value.ErrInvalid
	}
	presented, sign, err := r.Credential.Signer(ctx, value.ClusterCredentialRequest{Operation: operation, PodUID: request.Process.PodUID, ProcessEpoch: request.Process.ProcessEpoch, ClientKey: client, ServerKey: server, RequestedAt: r.Now().UTC().Truncate(time.Microsecond)})
	if err != nil {
		return zero, errors.Join(err, errRegionalCredential)
	}
	b := request.Process.Binding
	if presented.Profile.InstallationID != b.InstallationID || presented.Profile.ClusterID != b.ClusterID || presented.Profile.PeerID != b.PeerID {
		return zero, value.ErrInvalid // the credential belongs to another profile
	}
	finished := func() {}
	if r.Timing != nil {
		finished = r.Timing(purpose)
	}
	frame, err := r.Client.Run(ctx, func(exporter []byte) (connectorlifecycle.Opening, error) {
		signature, err := sign(exporter)
		if err != nil {
			return connectorlifecycle.Opening{}, err
		}
		o := connectorlifecycle.Opening{Presentation: clustercredential.Wire(presented, signature), Purpose: purpose, OperationID: id, Request: request, Certificate: leaf}
		if len(owner) == 1 {
			o.Owner = &owner[0]
		}
		return o, nil
	}, local)
	if err != nil {
		return zero, errRegionalChannel
	}
	if frame.Kind != "result" {
		return zero, errRegionalRefused
	}
	finished()
	return frame, nil
}

func (r *RegionalLifecycle) admitted() (value.ConnectorProcessRequest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil {
		return value.ConnectorProcessRequest{}, false
	}
	return *r.current, true
}

// ReadContextStartOwners asks the hub for its current context-start owner set
// (ADR-172), presented by this region's admitted process.
func (r *RegionalLifecycle) ReadContextStartOwners(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	request, ok := r.admitted()
	if !ok {
		return value.APIContextOwnerCandidates{}, value.ErrUnavailable
	}
	frame, err := r.run(ctx, connectorlifecycle.PurposeOwnerCandidates, value.ClusterRenewal, uuid.NewString(), request, nil)
	if err != nil || frame.Owners == nil || !frame.Owners.Valid(r.Now()) {
		return value.APIContextOwnerCandidates{}, unavailable(err)
	}
	return *frame.Owners, nil
}

// ReadOwnerObservationCandidates asks the hub for its owner observation
// candidates (ADR-197), presented by this region's admitted process.
func (r *RegionalLifecycle) ReadOwnerObservationCandidates(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	request, ok := r.admitted()
	if !ok {
		return value.APIContextOwnerCandidates{}, value.ErrUnavailable
	}
	frame, err := r.run(ctx, connectorlifecycle.PurposeOwnerObservationCandidates, value.ClusterRenewal, uuid.NewString(), request, nil)
	if err != nil || frame.Owners == nil || !frame.Owners.Valid(r.Now()) {
		return value.APIContextOwnerCandidates{}, unavailable(err)
	}
	return *frame.Owners, nil
}

// ReadOwnerRegistration asks the hub for one owner certificate's current
// registration (ADR-197), presented by this region's admitted process.
func (r *RegionalLifecycle) ReadOwnerRegistration(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	request, ok := r.admitted()
	if !ok {
		return value.OwnerRegistrationObservation{}, value.ErrUnavailable
	}
	frame, err := r.run(ctx, connectorlifecycle.PurposeOwnerRegistration, value.ClusterRenewal, uuid.NewString(), request, nil, c)
	if err != nil || frame.OwnerRegistration == nil || frame.OwnerRegistration.Certificate != c {
		return value.OwnerRegistrationObservation{}, unavailable(err)
	}
	return *frame.OwnerRegistration, nil
}

var _ fleetapp.RecoveryReader = (*RegionalLifecycle)(nil)

// RecoveryState asks the hub for its current recovery state, presented by this
// region's admitted process. It only feeds verify-only work trust; it can
// never clear or change recovery.
func (r *RegionalLifecycle) RecoveryState(ctx context.Context) (value.RecoveryState, error) {
	request, ok := r.admitted()
	if !ok {
		return value.RecoveryState{}, value.ErrUnavailable
	}
	frame, err := r.run(ctx, connectorlifecycle.PurposeRecovery, value.ClusterRenewal, uuid.NewString(), request, nil)
	if err != nil || frame.Recovery == nil || !frame.Recovery.Valid(r.Now()) || frame.Recovery.InstallationID != request.Process.Binding.InstallationID {
		return value.RecoveryState{}, unavailable(err)
	}
	return *frame.Recovery, nil
}

// AuthenticateOwner authenticates the owner of an actual TLS session: the hub
// supplies its registration, protection and route facts for the observed
// certificate, and this side verifies its own session against the returned
// configuration. The hub's answer alone authenticates nothing.
func (r *RegionalLifecycle) AuthenticateOwner(ctx context.Context, connection fleetapp.OwnerPeerConnection) (value.AuthenticatedOwner, error) {
	var zero value.AuthenticatedOwner
	request, ok := r.admitted()
	if !ok || connection == nil || ctx == nil {
		return zero, value.ErrUnavailable
	}
	certificate, err := connection.OwnerCertificate()
	if err != nil || certificate.Usage != "server" || !certificate.Valid(r.Now()) {
		return zero, value.ErrDenied
	}
	frame, err := r.run(ctx, connectorlifecycle.PurposeOwnerAuthentication, value.ClusterRenewal, uuid.NewString(), request, nil, certificate)
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
