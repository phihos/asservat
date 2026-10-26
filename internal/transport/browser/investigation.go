package browser

import (
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

// InvestigationHandler is inert until protected bootstrap mounts it. It shares
// the exact application operations with MCP; it contains no permission evaluator.
type InvestigationHandler struct {
	sessions   SessionHandler
	operations presentation.Operations
	audited    *presentation.AuditedOperations
	security   presentation.IngressCounters
	ingress    chan struct{}
	contracts  *contracts.InvestigationContracts
	slots      chan struct{}
	stopSlots  chan struct{}
	mu         sync.Mutex
	active     map[identity.Principal]int
	stopActive map[identity.Principal]int
	// Report receives a fixed stage label for every 503 (diagnostics only).
	Report func(string)
}

// NewInvestigationHandler is an unaudited component/test constructor, never
// an enabled-runtime choice. Use NewAuditedInvestigationHandler for the strict
// composition once protected bootstrap and capacity lifecycle are qualified.
func NewInvestigationHandler(sessions SessionHandler, operations presentation.Operations, maxConcurrent int) (*InvestigationHandler, error) {
	if sessions.Sessions == nil || !sessions.validOrigin() || operations == nil || operations.PublicOrigin() != sessions.Origin || maxConcurrent < 1 || maxConcurrent > 64 {
		return nil, presentation.ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &InvestigationHandler{sessions: sessions, operations: operations, ingress: make(chan struct{}, maxConcurrent), contracts: wire, slots: make(chan struct{}, maxConcurrent), stopSlots: make(chan struct{}, 4), active: map[identity.Principal]int{}, stopActive: map[identity.Principal]int{}}, nil
}

func NewAuditedInvestigationHandler(sessions SessionHandler, operations *presentation.AuditedOperations, maxConcurrent int) (*InvestigationHandler, error) {
	if operations == nil {
		return nil, presentation.ErrOperationsConfiguration
	}
	if _, ok := operations.Tool("prepare_artifact_download"); ok {
		return nil, presentation.ErrOperationsConfiguration
	}
	h, err := NewInvestigationHandler(sessions, operations, maxConcurrent)
	if err == nil {
		h.audited = operations
	}
	return h, err
}

// NewAuditedDownloadInvestigationHandler also serves the native download
// operations. Browser preparation is the same audited call as MCP's.
func NewAuditedDownloadInvestigationHandler(sessions SessionHandler, operations *presentation.AuditedOperations, maxConcurrent int) (*InvestigationHandler, error) {
	if operations == nil {
		return nil, presentation.ErrOperationsConfiguration
	}
	if _, ok := operations.Tool("prepare_artifact_download"); !ok {
		return nil, presentation.ErrOperationsConfiguration
	}
	if _, ok := operations.Tool("cancel_artifact_download"); !ok {
		return nil, presentation.ErrOperationsConfiguration
	}
	h, e := NewInvestigationHandler(sessions, operations, maxConcurrent)
	if e == nil {
		h.audited = operations
	}
	return h, e
}
func (h *InvestigationHandler) SecurityCounters() presentation.IngressSecuritySnapshot {
	return h.security.Snapshot()
}

func (h *InvestigationHandler) rejectIngress(w http.ResponseWriter, r *http.Request, current identities.CurrentIdentity, name string, body []byte, status int) {
	if h.audited != nil {
		until, err := h.audited.RejectBeforeDispatch(r.Context(), current, presentation.IngressRejection{RequestedOperation: name, Input: body, Kind: presentation.IngressInvalid})
		if err != nil {
			h.security.Add(presentation.IngressAuditUnavailable)
			sessionProblem(w, 503)
			return
		}
		final, err := current.ResolveIdentity(r.Context())
		if err != nil || r.Context().Err() != nil {
			sessionProblem(w, 503)
			return
		}
		until = identity.Earlier(until, final.ValidUntil)
		if !time.Now().Before(until) || http.NewResponseController(w).SetWriteDeadline(until) != nil {
			sessionProblem(w, 503)
			return
		}
	}
	sessionProblem(w, status)
}

func (h *InvestigationHandler) unavailable(w http.ResponseWriter, stage string) {
	if h.Report != nil {
		h.Report(stage)
	}
	sessionProblem(w, 503)
}

// failure is sessionFailure, reporting the stage when it answers 503.
func (h *InvestigationHandler) failure(w http.ResponseWriter, stage string, err error) {
	if h.Report != nil && !errors.Is(err, identity.ErrSessionBusy) && !errors.Is(err, identity.ErrDenied) && !errors.Is(err, identity.ErrInvalid) && !errors.Is(err, identity.ErrSessionCapacity) {
		var step interface{ FixedStep() string }
		if errors.As(err, &step) {
			stage += "/" + step.FixedStep()
		}
		h.Report(stage)
	}
	sessionFailure(w, err)
}

func (h *InvestigationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.sessions.base(w, r) {
		h.security.Add(presentation.IngressPreAdmission)
		return
	}
	const prefix = "/api/v1/operations/"
	if !strings.HasPrefix(r.URL.Path, prefix) || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		sessionProblem(w, 404)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, prefix)
	// Disabled mutation still has a bounded explicit browser error. MCP omits it
	// from discovery until enabled. Unknown operations never reach application.
	if h.audited == nil && !presentation.BrowserOperationSupported(h.operations, name) {
		sessionProblem(w, 404)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		sessionProblem(w, 405)
		return
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	invalidMedia := err != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) != 0
	if h.audited == nil && invalidMedia {
		sessionProblem(w, 400)
		return
	}
	// Authentication and parsing are bounded separately from execution. Long
	// ordinary provider calls release these slots before Stop classification.
	ingressHeld := false
	select {
	case h.ingress <- struct{}{}:
		ingressHeld = true
		defer func() {
			if ingressHeld {
				<-h.ingress
			}
		}()
	default:
		h.security.Add(presentation.IngressOverloaded)
		sessionProblem(w, 429)
		return
	}
	// Same per-operation window as MCP: evidence reads get the longer window.
	window := audit.OperationRequestWindow(name)
	ctx, cancel := context.WithTimeout(r.Context(), window)
	defer cancel()
	r = r.WithContext(ctx)
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	if controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		h.unavailable(w, "deadline-setup")
		return
	}
	current, view, err := h.sessions.AuthenticateCurrentWithin(w, r, window)
	if err != nil {
		h.security.Add(presentation.IngressPreAdmission)
		h.failure(w, "session", err)
		return
	}
	if invalidMedia {
		h.rejectIngress(w, r, current, name, []byte("unsupported-content-type-or-encoding"), 400)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, contracts.InvestigationInputLimit+1))
	defer clear(body)
	if len(body) > contracts.InvestigationInputLimit {
		h.security.Add(presentation.IngressOversized)
		sessionProblem(w, 413)
		return
	}
	if err != nil {
		h.security.Add(presentation.IngressPreAdmission)
		sessionProblem(w, 400)
		return
	}
	if !presentation.BrowserOperationSupported(h.operations, name) {
		h.rejectIngress(w, r, current, name, body, 404)
		return
	}
	if name == "request_capture" || name == "resolve_capture_request" || name == "prepare_artifact_download" || name == "cancel_artifact_download" || name == "activate_policy" {
		var input struct {
			Key string `json:"idempotency_key"`
		}
		if json.Unmarshal(body, &input) != nil || len(r.Header.Values("Idempotency-Key")) != 1 || input.Key == "" || r.Header.Get("Idempotency-Key") != input.Key {
			h.rejectIngress(w, r, current, name, body, 400)
			return
		}
	} else if len(r.Header.Values("Idempotency-Key")) != 0 {
		h.rejectIngress(w, r, current, name, body, 400)
		return
	}
	slots := h.slots
	if name == "cancel_artifact_download" && h.contracts.ValidateInput(name, body) == nil {
		if _, ok := h.operations.Tool(name); ok {
			slots = h.stopSlots
		}
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		h.security.Add(presentation.IngressOverloaded)
		sessionProblem(w, 429)
		return
	}
	<-h.ingress
	ingressHeld = false
	active := h.active
	if slots == h.stopSlots {
		active = h.stopActive
	}
	h.mu.Lock()
	if active[view.Identity.Principal] >= 4 {
		h.mu.Unlock()
		h.security.Add(presentation.IngressOverloaded)
		sessionProblem(w, 429)
		return
	}
	active[view.Identity.Principal]++
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		active[view.Identity.Principal]--
		if active[view.Identity.Principal] == 0 {
			delete(active, view.Identity.Principal)
		}
	}()
	var out presentation.OperationReply
	out, err = h.operations.Call(ctx, current, name, body)
	defer func() { _ = out.Close(ctx); clear(out.Body) }()
	if err != nil {
		if h.audited != nil {
			if out.ValidUntil.IsZero() {
				h.security.Add(presentation.IngressAuditUnavailable)
				h.unavailable(w, "call-no-outcome")
				return
			}
			final, e := current.ResolveIdentity(ctx)
			until := identity.Earlier(out.ValidUntil, final.ValidUntil)
			if e != nil || ctx.Err() != nil || !time.Now().Before(until) || controller.SetWriteDeadline(until) != nil {
				h.unavailable(w, "call-final-identity")
				return
			}
		}
		if errors.Is(err, contracts.ErrInvestigationWire) {
			sessionProblem(w, 400)
		} else {
			h.failure(w, "call", err)
		}
		return
	}
	// Recheck the original request-owned session after output validation, before
	// any metadata is sent. Cancellation never turns an unknown mutation into a
	// confirmed failure; the original key remains usable through the service.
	finalIdentity, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil {
		h.failure(w, "final-identity", identity.ErrDenied)
		return
	}
	if view.Identity.ValidUntil.Before(deadline) {
		deadline = view.Identity.ValidUntil
	}
	deadline = identity.Earlier(deadline, identity.Earlier(out.ValidUntil, finalIdentity.ValidUntil))
	if !time.Now().Before(deadline) {
		h.unavailable(w, "final-identity-expired")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	writeCtx, finishWrite := out.ResponseContext(ctx)
	defer finishWrite()
	if sent, err := presentation.WriteOperationResponse(writeCtx, w, http.StatusOK, out.Body, deadline, out.CheckDisclosure); err != nil && !sent {
		h.unavailable(w, "response-write")
	}
}
