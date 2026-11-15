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

// Services answers the presenting connector's read-only owner and recovery
// questions.
type Services interface {
	OwnerCandidates(context.Context, *Region) (value.APIContextOwnerCandidates, error)
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

// CapacityService records a connector's capacity delivery for its presented
// cluster (ADR-331), as AccessBindingsService.
type CapacityService interface {
	Capacity(context.Context, *Region) error
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
	region := &Region{conn: conn, presented: presented, verifiedAt: verifiedAt, process: opening.Process}
	defer region.closeChannel()
	result := HubFrame{Kind: "result"}
	switch opening.Purpose {
	case PurposeOwnerCandidates:
		var owners value.APIContextOwnerCandidates
		owners, err = h.services.OwnerCandidates(ctx, region)
		result.Owners = &owners
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
	case PurposeCapacity:
		if sink, ok := h.services.(CapacityService); ok {
			err = sink.Capacity(ctx, region)
		} else {
			err = ErrChannel
		}
	default:
		err = ErrChannel
	}
	if err != nil {
		result = HubFrame{Kind: "failure", Failure: "unavailable"} // never render internal errors
	}
	_ = conn.Send(result)
}

// admit binds the opening to the token's registered cluster: the process
// binding must name that cluster's peer.
func admit(o Opening, p value.ConnectorCluster) bool {
	if !authorization.UUID(o.OperationID) || !o.Process.Valid() {
		return false
	}
	switch o.Purpose {
	case PurposeOwnerCandidates, PurposeRecovery, PurposeAccessBindings, PurposeCapacity:
		if o.Owner != nil {
			return false
		}
	case PurposeOwnerAuthentication:
		if o.Owner == nil || o.Owner.Usage != "server" || o.Owner.Binding.InstallationID != o.Process.Binding.InstallationID {
			return false
		}
	default:
		return false
	}
	b := o.Process.Binding
	return p.InstallationID == b.InstallationID && p.ClusterID == b.ClusterID && p.PeerID == b.PeerID
}

// Region is one conversation's presenting connector: its token's cluster and
// at most one delivery read.
type Region struct {
	conn       *Conn
	presented  value.ConnectorCluster
	verifiedAt time.Time
	process    value.ConnectorProcessIdentity
	closed     bool
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
	if reply.Unchanged || reply.AccessBindings == nil || reply.Capacity != nil {
		r.closed = true
		return contracts.AccessBindingDelivery{}, false, ErrChannel
	}
	return *reply.AccessBindings, false, nil
}

// ReadCapacity asks the presenting connector for its capacity observation
// (ADR-331) like ReadAccessBindings, raising the read bound by the
// delivery's own byte bound.
func (r *Region) ReadCapacity(ctx context.Context, stored string) (_ contracts.CapacityDelivery, unchanged bool, _ error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()
	if r.delivered {
		return contracts.CapacityDelivery{}, false, ErrChannel
	}
	r.delivered = true
	r.conn.limit.n += contracts.CapacityDeliveryMaxBytes
	var reply RegionFrame
	if err := r.askFrame(ctx, HubFrame{Kind: "capacity", Digest: stored}, &reply); err != nil {
		return contracts.CapacityDelivery{}, false, err
	}
	if reply.Unchanged && reply.Capacity == nil && stored != "" {
		return contracts.CapacityDelivery{}, true, nil
	}
	if reply.Unchanged || reply.Capacity == nil || reply.AccessBindings != nil {
		r.closed = true
		return contracts.CapacityDelivery{}, false, ErrChannel
	}
	return *reply.Capacity, false, nil
}

func (r *Region) closeChannel() {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()
	r.closed = true
}

// OwnerReads are the hub's shared read-only owner facts for regional
// exchanges (ADR-172): the candidate set and the unchanged authenticator.
type OwnerReads struct {
	Candidates    app.APIContextOwnerCandidatesReader
	Authenticator *app.OwnerAuthenticator
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

// Duties are the hub's read-only answers for every presenting connector.
type Duties struct {
	Owners    OwnerReads
	Recoverer app.RecoveryReader
}

func (d Duties) OwnerCandidates(ctx context.Context, _ *Region) (value.APIContextOwnerCandidates, error) {
	if d.Owners.Candidates == nil {
		return value.APIContextOwnerCandidates{}, ErrChannel
	}
	return d.Owners.Candidates.ReadContextStartOwners(ctx)
}

func (d Duties) AuthenticateOwner(ctx context.Context, _ *Region, c value.OwnerCertificate) (OwnerAuthentication, error) {
	if d.Owners.Authenticator == nil {
		return OwnerAuthentication{}, ErrChannel
	}
	var configuration value.OwnerConfigurationObservation
	owner, err := d.Owners.Authenticator.AuthenticateOwner(ctx, presentedOwner{c, &configuration})
	if err != nil {
		return OwnerAuthentication{}, err
	}
	return OwnerAuthentication{Owner: owner, Configuration: configuration}, nil
}

func (d Duties) Recovery(ctx context.Context, _ *Region) (value.RecoveryState, error) {
	if d.Recoverer == nil {
		return value.RecoveryState{}, ErrChannel
	}
	return d.Recoverer.RecoveryState(ctx)
}
