package connectorlifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/clustercredential"
)

// Services runs the hub's unchanged duties for the presenting peer. The Region
// is that conversation's delegated native and source reader.
type Services interface {
	Enroll(context.Context, *Region, string, value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error)
	Issue(context.Context, *Region, string, string, value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error)
	Registration(context.Context, *Region, value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error)
	OwnerCandidates(context.Context, *Region) (value.APIContextOwnerCandidates, error)
	OwnerObservationCandidates(context.Context, *Region) (value.APIContextOwnerCandidates, error)
	OwnerRegistration(context.Context, *Region, value.OwnerCertificate) (value.OwnerRegistrationObservation, error)
	AuthenticateOwner(context.Context, *Region, value.OwnerCertificate) (OwnerAuthentication, error)
	Recovery(context.Context, *Region) (value.RecoveryState, error)
}

// BootstrapService enrolls generation 1 (ADR-193). The handler has already
// verified the CSR key, the secret and the exporter-bound signature.
type BootstrapService interface {
	Bootstrap(context.Context, *Region, value.ClusterBootstrapRequest, ed25519.PublicKey) (value.ClusterBootstrapResult, error)
}

type Handler struct {
	presenter clustercredential.Presenter
	keys      app.EnrollmentProofVerifier
	services  Services
	slots     chan struct{}
}

func NewHandler(p clustercredential.Presenter, keys app.EnrollmentProofVerifier, services Services, concurrency int) (*Handler, error) {
	if p == nil || keys == nil || services == nil || concurrency < 1 || concurrency > 16 {
		return nil, ErrChannel
	}
	return &Handler{p, keys, services, make(chan struct{}, concurrency)}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	fail := func(code int) { w.Header().Set("Connection", "close"); w.WriteHeader(code) }
	if h == nil || r.ProtoMajor != 2 || r.Method != http.MethodPost || r.URL.Path != Path || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != ContentType || len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Cookie")) != 0 {
		fail(http.StatusBadRequest)
		return
	}
	exporter, err := clustercredential.Exporter(r.TLS)
	if err != nil {
		fail(http.StatusForbidden)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		fail(http.StatusTooManyRequests)
		return
	}
	// One finite conversation; the lifecycle services keep their own shorter
	// original five-second operation bounds inside it.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	control := http.NewResponseController(w)
	if control.EnableFullDuplex() != nil {
		fail(http.StatusInternalServerError)
		return
	}
	conn := NewConn(r.Body, w, control.Flush, control.SetReadDeadline)
	var opening Opening
	if conn.Receive(ctx, &opening) != nil {
		fail(http.StatusBadRequest)
		return
	}
	if opening.Purpose == PurposeBootstrap {
		h.serveBootstrap(ctx, w, control, conn, opening, exporter)
		return
	}
	presented, ok := h.admit(ctx, opening, exporter)
	if !ok {
		fail(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	if control.Flush() != nil {
		return
	}
	region := &Region{conn: conn, presented: presented, process: opening.Request.Process}
	defer region.closeChannel()
	result := HubFrame{Kind: "result"}
	switch opening.Purpose {
	case value.ConnectorLifecycleEnroll:
		var process value.ConnectorCredentialProcess
		process, err = h.services.Enroll(ctx, region, opening.OperationID, opening.Request)
		result.Process = &process
	case PurposeOwnerCandidates:
		var owners value.APIContextOwnerCandidates
		owners, err = h.services.OwnerCandidates(ctx, region)
		result.Owners = &owners
	case PurposeOwnerObservationCandidates:
		var owners value.APIContextOwnerCandidates
		owners, err = h.services.OwnerObservationCandidates(ctx, region)
		result.Owners = &owners
	case PurposeOwnerRegistration:
		var registration value.OwnerRegistrationObservation
		registration, err = h.services.OwnerRegistration(ctx, region, *opening.Owner)
		if err == nil && registration.Certificate != *opening.Owner {
			err = ErrChannel // only the requested certificate, never another owner
		}
		result.OwnerRegistration = &registration
	case PurposeRecovery:
		var recovery value.RecoveryState
		recovery, err = h.services.Recovery(ctx, region)
		if err == nil && recovery.InstallationID != region.Presented().Profile.InstallationID {
			err = ErrChannel // only the presenting installation's own state
		}
		result.Recovery = &recovery
	case PurposeOwnerAuthentication:
		var owner OwnerAuthentication
		owner, err = h.services.AuthenticateOwner(ctx, region, *opening.Owner)
		if err == nil && owner.Owner.Certificate != *opening.Owner {
			err = ErrChannel // only the observed certificate, never another owner
		}
		result.Owner = &owner
	case PurposeRegistration:
		var registration app.ConnectorLeafRegistration
		registration, err = h.services.Registration(ctx, region, *opening.Certificate)
		if err == nil && (registration.Process != opening.Request.Process || registration.Certificate != *opening.Certificate) {
			err = ErrChannel // only this process's own leaf, never another's
		}
		result.Registration = &registration
	default:
		usage := "client"
		if opening.Purpose == value.ConnectorLifecycleServer {
			usage = "server"
		}
		var issued value.IssuedConnectorCredential
		issued, err = h.services.Issue(ctx, region, opening.OperationID, usage, opening.Request)
		result.Credential = &issued
	}
	if err != nil {
		result = HubFrame{Kind: "failure", Failure: "unavailable"} // never render internal errors
	}
	_ = conn.Send(result)
}

// serveBootstrap checks the bootstrap opening before any reply: the CSR's
// Ed25519 key matches the signed digest, the secret matches its digest and
// the signature binds this connection. The conversation is then bound to the
// claimed slot by the service.
func (h *Handler) serveBootstrap(ctx context.Context, w http.ResponseWriter, control *http.ResponseController, conn *Conn, o Opening, exporter []byte) {
	fail := func(code int) { w.Header().Set("Connection", "close"); w.WriteHeader(code) }
	service, ok := h.services.(BootstrapService)
	proof, proofs := h.keys.(app.ClusterBootstrapProof)
	b := o.Bootstrap
	empty, _ := json.Marshal(contracts.ClusterCredentialWire{})
	presentation, _ := json.Marshal(o.Presentation)
	if !ok || !proofs || b == nil || o.OperationID != "" || o.Certificate != nil || o.Owner != nil || !bytes.Equal(presentation, empty) || !b.Request.Valid() {
		fail(http.StatusForbidden)
		return
	}
	key, digest, err := proof.BootstrapKey(b.CSRDER)
	secret, serr := proof.BootstrapSecretDigest(b.Request.InstallationID, b.Request.BootstrapID, b.Secret)
	skew := time.Since(b.Request.RequestedAt)
	if err != nil || serr != nil || digest != b.Request.KeyDigest || secret != b.Request.SecretDigest || skew > 30*time.Second || skew < -30*time.Second ||
		!app.VerifyClusterBootstrapRequest(key, b.Request, b.Signature, exporter) {
		fail(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	if control.Flush() != nil {
		return
	}
	region := &Region{conn: conn}
	defer region.closeChannel()
	result, err := service.Bootstrap(ctx, region, b.Request, key)
	frame := HubFrame{Kind: "result", Bootstrap: &result}
	if errors.Is(err, value.ErrClusterCredentialFenced) {
		frame = HubFrame{Kind: "failure", Failure: "fenced"}
	} else if err != nil {
		frame = HubFrame{Kind: "failure", Failure: "unavailable"}
	}
	_ = conn.Send(frame)
}

// admit binds the exporter-bound ADR-168 presentation to this exact request:
// the profile, the process and both CSR key digests.
func (h *Handler) admit(ctx context.Context, o Opening, exporter []byte) (value.ClusterCredentialPresentation, bool) {
	var zero value.ClusterCredentialPresentation
	if !authorization.UUID(o.OperationID) || !o.Request.Valid() {
		return zero, false
	}
	operation := value.ClusterRenewal
	switch o.Purpose {
	case value.ConnectorLifecycleEnroll:
		operation = value.ClusterAdmission
	case value.ConnectorLifecycleClient, value.ConnectorLifecycleServer:
	case PurposeRegistration:
		if o.Certificate == nil || o.Certificate.Binding != o.Request.Process.Binding {
			return zero, false
		}
	case PurposeOwnerCandidates, PurposeRecovery, PurposeOwnerObservationCandidates:
	case PurposeOwnerAuthentication, PurposeOwnerRegistration:
		if o.Owner == nil || o.Owner.Usage != "server" || o.Owner.Binding.InstallationID != o.Request.Process.Binding.InstallationID {
			return zero, false
		}
	default:
		return zero, false
	}
	if o.Purpose != PurposeRegistration && o.Certificate != nil || o.Purpose != PurposeOwnerAuthentication && o.Purpose != PurposeOwnerRegistration && o.Owner != nil {
		return zero, false
	}
	request, err := clustercredential.Request(o.Presentation)
	if err != nil || request.Operation != operation {
		return zero, false
	}
	b := o.Request.Process.Binding
	if request.Profile.InstallationID != b.InstallationID || request.Profile.ClusterID != b.ClusterID || request.Profile.PeerID != b.PeerID || request.PodUID != o.Request.Process.PodUID || request.ProcessEpoch != o.Request.Process.ProcessEpoch {
		return zero, false
	}
	client, err := h.keys.EnrollmentKey(o.Request.ClientCSRDER)
	if err != nil || client != request.ClientKey {
		return zero, false
	}
	server, err := h.keys.EnrollmentKey(o.Request.ServerCSRDER)
	if err != nil || server != request.ServerKey {
		return zero, false
	}
	p, err := h.presenter.Present(ctx, request, o.Presentation.Signature, exporter)
	return p, err == nil
}

// Region is one conversation's delegated regional reader: ADR-153 native
// phases for exactly one begun operation, plus protected source and
// configuration values. Every value is checked against the presented peer;
// the hub duties still apply all of their own domain and SQL checks.
type Region struct {
	conn      *Conn
	presented value.ClusterCredentialPresentation
	process   value.ConnectorProcessIdentity
	begun     *app.ConnectorLifecycleRequest
	closed    bool
	// slot is the claimed bootstrap slot of a bootstrap conversation; every
	// source value is checked against it instead of a presentation.
	slot *value.PeerBinding
}

// BindBootstrap binds a bootstrap conversation to its claimed slot, once.
func (r *Region) BindBootstrap(b value.PeerBinding) error {
	if r == nil || r.slot != nil || r.presented.Profile != (value.ClusterCredentialProfile{}) || !b.Valid() || b.Role != value.ConnectorPeer {
		return ErrChannel
	}
	r.slot = &b
	return nil
}

// Presented is the verified ADR-168 presentation that opened the conversation.
func (r *Region) Presented() value.ClusterCredentialPresentation { return r.presented }

func (r *Region) peer(b value.PeerBinding) bool {
	if r.slot != nil {
		return b == *r.slot
	}
	p := r.presented.Profile
	return b == r.process.Binding && b.InstallationID == p.InstallationID && b.ClusterID == p.ClusterID && b.PeerID == p.PeerID
}

// ask sends one payload-free request frame and receives its reply under the
// channel lock. Any failure closes the channel.
func (r *Region) ask(ctx context.Context, kind string, reply *RegionFrame) error {
	if r.closed || ctx == nil {
		return ErrChannel
	}
	if r.conn.Send(HubFrame{Kind: kind}) != nil {
		r.closed = true
		return ErrChannel
	}
	if err := r.conn.Receive(ctx, reply); err != nil || reply.Kind != kind {
		r.closed = true
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return err
		}
		return ErrChannel
	}
	return nil
}

func (r *Region) ReadConnectorIdentitySource(ctx context.Context) (value.ConnectorIdentitySource, error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()
	var reply RegionFrame
	if err := r.ask(ctx, "source", &reply); err != nil {
		return value.ConnectorIdentitySource{}, err
	}
	if reply.Source == nil || !r.peer(reply.Source.Observation.Profile.Binding) {
		r.closed = true
		return value.ConnectorIdentitySource{}, ErrChannel
	}
	return *reply.Source, nil
}

func (r *Region) ReadConnectorIdentityConfiguration(ctx context.Context) (app.ConnectorIdentityConfiguration, error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()
	var reply RegionFrame
	if err := r.ask(ctx, "configuration", &reply); err != nil {
		return app.ConnectorIdentityConfiguration{}, err
	}
	if reply.Configuration == nil || !r.peer(reply.Configuration.Source.Observation.Profile.Binding) {
		r.closed = true
		return app.ConnectorIdentityConfiguration{}, ErrChannel
	}
	return *reply.Configuration, nil
}

func (r *Region) BeginConnectorLifecycle(ctx context.Context, req app.ConnectorLifecycleRequest) (app.ConnectorLifecycleOperation, error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()
	if r.begun != nil || r.closed || ctx == nil || req.Binding.Process != r.process {
		return nil, ErrChannel
	}
	if r.conn.Send(HubFrame{Kind: "begin", Begin: &req}) != nil {
		return nil, ErrChannel
	}
	var reply RegionFrame
	if r.conn.Receive(ctx, &reply) != nil || reply.Kind != "begun" || reply.Observation != nil {
		r.closed = true
		return nil, ErrChannel
	}
	r.begun = &req
	return &remoteOperation{r}, nil
}

func (r *Region) closeChannel() {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()
	r.closed = true
}

type remoteOperation struct{ reader *Region }

func (o *remoteOperation) Read(ctx context.Context, phase value.ConnectorLifecyclePhase) (value.ConnectorLifecycleObservation, error) {
	r := o.reader
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()
	var zero value.ConnectorLifecycleObservation
	if r.closed || r.begun == nil || ctx == nil {
		return zero, ErrChannel
	}
	if r.conn.Send(HubFrame{Kind: "read", Phase: phase}) != nil {
		r.closed = true
		return zero, ErrChannel
	}
	var reply RegionFrame
	if err := r.conn.Receive(ctx, &reply); err != nil || reply.Kind != "observation" || reply.Observation == nil {
		r.closed = true
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return zero, err
		}
		return zero, ErrChannel
	}
	obs := reply.Observation.Clone()
	b, want := obs.Binding, r.begun.Binding
	if obs.Phase != phase || b.ID != want.ID || b.Purpose != want.Purpose || b.Process != want.Process || !b.RequestedAt.Equal(want.RequestedAt) || !b.NotAfter.Equal(want.NotAfter) {
		r.closed = true
		return zero, ErrChannel
	}
	return obs, nil // the lifecycle service still applies every domain check
}

func (o *remoteOperation) Close() {
	r := o.reader
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()
	if !r.closed {
		_ = r.conn.Send(HubFrame{Kind: "close"})
	}
	r.closed = true
}

// OwnerReads are the hub's shared read-only owner facts for regional
// exchanges (ADR-172): the candidate set and the unchanged authenticator.
type OwnerReads struct {
	Candidates    app.APIContextOwnerCandidatesReader
	Authenticator *app.OwnerAuthenticator
	// ADR-197: the regional capacity observation's owner reads.
	ObservationCandidates app.OwnerObservationCandidatesReader
	Registry              app.OwnerCertificateRegistry
}

// presentedOwner lets the hub's authenticator check a certificate the region
// observed. It cannot see that TLS session, so its verify step only requires
// the identical certificate and records the configuration for the region.
type presentedOwner struct {
	certificate   value.OwnerCertificate
	configuration *value.OwnerConfigurationObservation
}

func (p presentedOwner) OwnerCertificate() (value.OwnerCertificate, error) { return p.certificate, nil }
func (p presentedOwner) VerifyCurrentOwner(c value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
	if p.configuration.Configuration.Valid() {
		if !p.configuration.Configuration.Equal(c.Configuration) {
			return value.OwnerCertificate{}, value.ErrDenied
		}
	} else {
		*p.configuration = c
	}
	return p.certificate, nil
}

// PeerDuties are one peer's unchanged hub duties. Enrollment, Renewal and
// Source have their readers replaced by the conversation's Region; Registry
// builds the SQL leaf registry over that conversation's source reader.
type PeerDuties struct {
	Enrollment app.ConnectorLifecycleEnrollment
	Renewal    app.ConnectorLifecycleRenewal
	Source     app.ConnectorIdentityObserver
	Registry   func(context.Context, app.ConnectorIdentitySourceReader) (app.ConnectorLeafRegistry, error)
	Owners     OwnerReads
	Recovery   app.RecoveryReader
}

// Runners selects the duties of exactly the presented peer. An unknown or
// unconfigured peer is an error; it never falls back to another profile.
type Runners func(context.Context, value.ClusterCredentialProfile) (PeerDuties, error)

// Enroll stages the delegated source first: staging only creates a candidate
// or a fence, and admission still requires the separately accepted source.
func (s Runners) Enroll(ctx context.Context, region *Region, id string, r value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	d, err := s(ctx, region.Presented().Profile)
	if err != nil {
		return value.ConnectorCredentialProcess{}, err
	}
	source := d.Source
	source.Reader = region
	if err = source.Observe(ctx); err != nil {
		return value.ConnectorCredentialProcess{}, err
	}
	e := d.Enrollment
	e.Native = region
	return e.Enroll(ctx, id, r)
}

func (s Runners) Issue(ctx context.Context, region *Region, id, usage string, r value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error) {
	d, err := s(ctx, region.Presented().Profile)
	if err != nil {
		return value.IssuedConnectorCredential{}, err
	}
	e := d.Renewal
	e.Native = region
	return e.IssueProcess(ctx, id, usage, r)
}

func (s Runners) Registration(ctx context.Context, region *Region, c value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
	d, err := s(ctx, region.Presented().Profile)
	if err != nil || d.Registry == nil {
		return app.ConnectorLeafRegistration{}, ErrChannel
	}
	registry, err := d.Registry(ctx, region)
	if err != nil {
		return app.ConnectorLeafRegistration{}, err
	}
	return registry.ConnectorLeafRegistration(ctx, c)
}

func (s Runners) OwnerCandidates(ctx context.Context, region *Region) (value.APIContextOwnerCandidates, error) {
	d, err := s(ctx, region.Presented().Profile)
	if err != nil || d.Owners.Candidates == nil {
		return value.APIContextOwnerCandidates{}, ErrChannel
	}
	return d.Owners.Candidates.ReadContextStartOwners(ctx)
}

func (s Runners) OwnerObservationCandidates(ctx context.Context, region *Region) (value.APIContextOwnerCandidates, error) {
	d, err := s(ctx, region.Presented().Profile)
	if err != nil || d.Owners.ObservationCandidates == nil {
		return value.APIContextOwnerCandidates{}, ErrChannel
	}
	return d.Owners.ObservationCandidates.ReadOwnerObservationCandidates(ctx)
}

func (s Runners) OwnerRegistration(ctx context.Context, region *Region, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	d, err := s(ctx, region.Presented().Profile)
	if err != nil || d.Owners.Registry == nil {
		return value.OwnerRegistrationObservation{}, ErrChannel
	}
	return d.Owners.Registry.ReadOwnerRegistration(ctx, c)
}

func (s Runners) AuthenticateOwner(ctx context.Context, region *Region, c value.OwnerCertificate) (OwnerAuthentication, error) {
	d, err := s(ctx, region.Presented().Profile)
	if err != nil || d.Owners.Authenticator == nil {
		return OwnerAuthentication{}, ErrChannel
	}
	var configuration value.OwnerConfigurationObservation
	owner, err := d.Owners.Authenticator.AuthenticateOwner(ctx, presentedOwner{c, &configuration})
	if err != nil {
		return OwnerAuthentication{}, err
	}
	return OwnerAuthentication{Owner: owner, Configuration: configuration}, nil
}

func (s Runners) Recovery(ctx context.Context, region *Region) (value.RecoveryState, error) {
	d, err := s(ctx, region.Presented().Profile)
	if err != nil || d.Recovery == nil {
		return value.RecoveryState{}, ErrChannel
	}
	return d.Recovery.RecoveryState(ctx)
}
