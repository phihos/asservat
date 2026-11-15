package connectorlifecycle

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
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

// TokenVerifier attributes a connector's projected ServiceAccount token to
// its registered cluster (ADR-334).
type TokenVerifier interface {
	VerifyConnector(context.Context, string) (value.ConnectorCluster, error)
}

// AccessBindingsService records a connector's AccessBinding delivery for its
// presented cluster (ADR-329). The Region reads the delivery; the service
// must attribute it to region.Presented().ClusterID only.
type AccessBindingsService interface {
	AccessBindings(context.Context, *Region) error
}

type Handler struct {
	tokens   TokenVerifier
	services Services
	slots    chan struct{}
}

func NewHandler(tokens TokenVerifier, services Services, concurrency int) (*Handler, error) {
	if tokens == nil || services == nil || concurrency < 1 {
		return nil, ErrChannel
	}
	return &Handler{tokens, services, make(chan struct{}, concurrency)}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	fail := func(code int) { w.Header().Set("Connection", "close"); w.WriteHeader(code) }
	if h == nil || r.ProtoMajor != 2 || r.Method != http.MethodPost || r.URL.Path != Path || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != ContentType || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("Cookie")) != 0 {
		fail(http.StatusBadRequest)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		fail(http.StatusUnauthorized)
		return
	}
	// The token is verified before any slot or opening read: an
	// unauthenticated caller holds no concurrency slot and sends no frame.
	verify, endVerify := context.WithTimeout(r.Context(), 5*time.Second)
	presented, err := h.tokens.VerifyConnector(verify, token)
	endVerify()
	if err != nil {
		fail(http.StatusUnauthorized)
		return
	}
	verifiedAt := time.Now()
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
	if !admit(opening, presented) {
		fail(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	if control.Flush() != nil {
		return
	}
	region := &Region{conn: conn, presented: presented, verifiedAt: verifiedAt, process: opening.Request.Process}
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
		if err == nil && recovery.InstallationID != region.Presented().InstallationID {
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
	case PurposeAccessBindings:
		if sink, ok := h.services.(AccessBindingsService); ok {
			err = sink.AccessBindings(ctx, region)
		} else {
			err = ErrChannel
		}
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

// admit binds the opening to the token's registered cluster: the process
// binding must name that cluster's peer.
func admit(o Opening, p value.ConnectorCluster) bool {
	if !authorization.UUID(o.OperationID) || !o.Request.Valid() {
		return false
	}
	switch o.Purpose {
	case value.ConnectorLifecycleEnroll, value.ConnectorLifecycleClient, value.ConnectorLifecycleServer:
	case PurposeRegistration:
		if o.Certificate == nil || o.Certificate.Binding != o.Request.Process.Binding {
			return false
		}
	case PurposeOwnerCandidates, PurposeRecovery, PurposeOwnerObservationCandidates, PurposeAccessBindings:
	case PurposeOwnerAuthentication, PurposeOwnerRegistration:
		if o.Owner == nil || o.Owner.Usage != "server" || o.Owner.Binding.InstallationID != o.Request.Process.Binding.InstallationID {
			return false
		}
	default:
		return false
	}
	if o.Purpose != PurposeRegistration && o.Certificate != nil || o.Purpose != PurposeOwnerAuthentication && o.Purpose != PurposeOwnerRegistration && o.Owner != nil {
		return false
	}
	b := o.Request.Process.Binding
	return p.InstallationID == b.InstallationID && p.ClusterID == b.ClusterID && p.PeerID == b.PeerID
}

// Region is one conversation's delegated regional reader: ADR-153 native
// phases for exactly one begun operation, plus protected source and
// configuration values. Every value is checked against the presented peer;
// the hub duties still apply all of their own domain and SQL checks.
type Region struct {
	conn      *Conn
	presented  value.ConnectorCluster
	verifiedAt time.Time
	process    value.ConnectorProcessIdentity
	begun     *app.ConnectorLifecycleRequest
	closed    bool
	// delivered marks the conversation's one AccessBinding or capacity
	// request.
	delivered bool
}

// Presented is the cluster the conversation's token was attributed to.
func (r *Region) Presented() value.ConnectorCluster { return r.presented }

// VerifiedAt is when the token was verified; deliveries are observed no later.
func (r *Region) VerifiedAt() time.Time { return r.verifiedAt }

// Binding is the presenting process's peer binding, checked against the cluster.
func (r *Region) Binding() value.PeerBinding { return r.process.Binding }

func (r *Region) peer(b value.PeerBinding) bool {
	p := r.presented
	return b == r.process.Binding && b.InstallationID == p.InstallationID && b.ClusterID == p.ClusterID && b.PeerID == p.PeerID
}

// ask sends one payload-free request frame and receives its reply under the
// channel lock. Any failure closes the channel.
func (r *Region) ask(ctx context.Context, kind string, reply *RegionFrame) error {
	return r.askFrame(ctx, HubFrame{Kind: kind}, reply)
}

func (r *Region) askFrame(ctx context.Context, frame HubFrame, reply *RegionFrame) error {
	kind := frame.Kind
	if r.closed || ctx == nil {
		return ErrChannel
	}
	if r.conn.Send(frame) != nil {
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

// ReadAccessBindings asks the presenting connector for its cluster's complete
// AccessBinding LIST (ADR-329), once per conversation, with the hub's stored
// digest: unchanged reports that the connector's current delivery has it.
// Only this request raises the conversation's read bound, by the delivery's
// own byte bound.
func (r *Region) ReadAccessBindings(ctx context.Context, stored string) (_ contracts.AccessBindingDelivery, unchanged bool, _ error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()
	if r.delivered {
		return contracts.AccessBindingDelivery{}, false, ErrChannel
	}
	r.delivered = true
	r.conn.limit.n += contracts.AccessBindingDeliveryMaxBytes
	var reply RegionFrame
	if err := r.askFrame(ctx, HubFrame{Kind: "access-bindings", Digest: stored}, &reply); err != nil {
		return contracts.AccessBindingDelivery{}, false, err
	}
	if reply.Unchanged && reply.AccessBindings == nil && stored != "" {
		return contracts.AccessBindingDelivery{}, true, nil
	}
	if reply.Unchanged || reply.AccessBindings == nil || reply.Source != nil || reply.Configuration != nil || reply.Observation != nil {
		r.closed = true
		return contracts.AccessBindingDelivery{}, false, ErrChannel
	}
	return *reply.AccessBindings, false, nil
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
type Runners func(context.Context, *Region) (PeerDuties, error)

// Enroll stages the delegated source first: staging only creates a candidate
// or a fence, and admission still requires the separately accepted source.
func (s Runners) Enroll(ctx context.Context, region *Region, id string, r value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	d, err := s(ctx, region)
	if err != nil {
		return value.ConnectorCredentialProcess{}, enrollmentError{"resolve", err}
	}
	source := d.Source
	source.Reader = region
	if err = source.Observe(ctx); err != nil {
		return value.ConnectorCredentialProcess{}, enrollmentError{"source", err}
	}
	e := d.Enrollment
	e.Native = region
	return e.Enroll(ctx, id, r)
}

func (s Runners) Issue(ctx context.Context, region *Region, id, usage string, r value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error) {
	d, err := s(ctx, region)
	if err != nil {
		return value.IssuedConnectorCredential{}, err
	}
	e := d.Renewal
	e.Native = region
	return e.IssueProcess(ctx, id, usage, r)
}

func (s Runners) Registration(ctx context.Context, region *Region, c value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
	d, err := s(ctx, region)
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
	d, err := s(ctx, region)
	if err != nil || d.Owners.Candidates == nil {
		return value.APIContextOwnerCandidates{}, ErrChannel
	}
	return d.Owners.Candidates.ReadContextStartOwners(ctx)
}

func (s Runners) OwnerObservationCandidates(ctx context.Context, region *Region) (value.APIContextOwnerCandidates, error) {
	d, err := s(ctx, region)
	if err != nil || d.Owners.ObservationCandidates == nil {
		return value.APIContextOwnerCandidates{}, ErrChannel
	}
	return d.Owners.ObservationCandidates.ReadOwnerObservationCandidates(ctx)
}

func (s Runners) OwnerRegistration(ctx context.Context, region *Region, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	d, err := s(ctx, region)
	if err != nil || d.Owners.Registry == nil {
		return value.OwnerRegistrationObservation{}, ErrChannel
	}
	return d.Owners.Registry.ReadOwnerRegistration(ctx, c)
}

func (s Runners) AuthenticateOwner(ctx context.Context, region *Region, c value.OwnerCertificate) (OwnerAuthentication, error) {
	d, err := s(ctx, region)
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
	d, err := s(ctx, region)
	if err != nil || d.Recovery == nil {
		return value.RecoveryState{}, ErrChannel
	}
	return d.Recovery.RecoveryState(ctx)
}

// enrollmentError names the two pre-runner boundaries without provider text.
type enrollmentError struct {
	step string
	err  error
}

func (e enrollmentError) Error() string     { return "connector enrollment " + e.step }
func (e enrollmentError) Unwrap() error     { return e.err }
func (e enrollmentError) FixedStep() string { return e.step }
func EnrollmentStep(err error) string {
	var failure enrollmentError
	if errors.As(err, &failure) {
		return failure.step
	}
	return app.ConnectorEnrollmentStep(err)
}
