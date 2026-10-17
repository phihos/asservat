package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	app "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/fleet"
)

// FleetBootstrapPath is the ADR-193 fleet-operator bootstrap issuance route.
const FleetBootstrapPath = "/api/v1/fleet/cluster-bootstraps"

// FleetBootstrapService is the audited issuance; the handler supplies only the
// request's current identity and the parsed operator input.
type FleetBootstrapService interface {
	Issue(context.Context, app.CurrentIdentity, fleetapp.FleetBootstrapRequest) (value.BootstrapIntent, error)
}

// FleetHandler serves the issuance route: session, CSRF and an
// Idempotency-Key header; one request in flight per principal and two in
// total. The reply is the slot reference; the secret stays in the channel.
type FleetHandler struct {
	sessions SessionHandler
	service  FleetBootstrapService
	slots    chan struct{}
	mu       sync.Mutex
	active   map[string]bool
}

func NewFleetHandler(sessions SessionHandler, service FleetBootstrapService) (*FleetHandler, error) {
	if sessions.Sessions == nil || service == nil {
		return nil, errors.New("fleet handler configuration")
	}
	return &FleetHandler{sessions: sessions, service: service, slots: make(chan struct{}, 2), active: map[string]bool{}}, nil
}

type fleetBootstrapInput struct {
	DisplayName     string `json:"displayName"`
	Region          string `json:"region"`
	DeliveryProfile string `json:"deliveryProfile"`
}

type fleetBootstrapReply struct {
	BootstrapID       string    `json:"bootstrapID"`
	ClusterID         string    `json:"clusterID"`
	PeerID            string    `json:"peerID"`
	IssuerEpoch       string    `json:"issuerEpoch"`
	DeliveryProfile   string    `json:"deliveryProfile"`
	CredentialVersion int       `json:"credentialVersion"`
	NotBefore         time.Time `json:"notBefore"`
	NotAfter          time.Time `json:"notAfter"`
}

func (h *FleetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.sessions.base(w, r) {
		return
	}
	if r.URL.Path != FleetBootstrapPath || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		sessionProblem(w, 404)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		sessionProblem(w, 405)
		return
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && params["charset"] != "utf-8" || len(r.Header.Values("Content-Encoding")) != 0 || len(r.Header.Values("Idempotency-Key")) != 1 {
		sessionProblem(w, 400)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		sessionProblem(w, 429)
		return
	}
	// The current identity stays valid for five seconds from the request
	// start, so a slow issuance fails its re-authorization and the same
	// Idempotency-Key resumes it; nothing extends that window.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	current, view, err := h.sessions.AuthenticateCurrent(w, r.WithContext(ctx))
	if err != nil {
		sessionFailure(w, err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	var in fleetBootstrapInput
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err != nil || len(body) > 4096 || d.Decode(&in) != nil || d.More() {
		sessionProblem(w, 400)
		return
	}
	principal := view.Identity.Principal.Issuer + "\x00" + view.Identity.Principal.Subject
	h.mu.Lock()
	if h.active[principal] {
		h.mu.Unlock()
		sessionProblem(w, 429)
		return
	}
	h.active[principal] = true
	h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.active, principal); h.mu.Unlock() }()
	intent, err := h.service.Issue(ctx, current, fleetapp.FleetBootstrapRequest{DisplayName: in.DisplayName, Region: in.Region, DeliveryProfile: in.DeliveryProfile, IdempotencyKey: r.Header.Get("Idempotency-Key")})
	switch {
	case errors.Is(err, value.ErrDenied):
		sessionProblem(w, 403)
		return
	case errors.Is(err, value.ErrInvalid):
		sessionProblem(w, 400)
		return
	case errors.Is(err, value.ErrCapacity):
		sessionProblem(w, http.StatusTooManyRequests) // a fleet.json ceiling
		return
	case err != nil || !intent.Issued || intent.Credential == nil:
		sessionProblem(w, 503)
		return
	}
	s := intent.Slot
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(fleetBootstrapReply{BootstrapID: s.ID, ClusterID: s.Binding.ClusterID, PeerID: s.Binding.PeerID, IssuerEpoch: s.Binding.IssuerEpoch, DeliveryProfile: s.DeliveryProfile, CredentialVersion: intent.Credential.Version, NotBefore: s.NotBefore, NotAfter: s.NotAfter})
}
