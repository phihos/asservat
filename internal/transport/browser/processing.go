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

	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

// ProcessingChangesPath is the ADR-210 privacy-operator processing route.
const ProcessingChangesPath = "/api/v1/processing/changes"

// ProcessingChangeService is the audited processing change; the handler
// supplies only the request's current identity and the parsed change.
type ProcessingChangeService interface {
	Change(context.Context, app.CurrentIdentity, value.ProcessingChange) (value.ProcessingReceipt, error)
}

// ProcessingHandler serves the processing route like the fleet route:
// session, CSRF, exact JSON and an Idempotency-Key header that is the
// change's request ID, one request per principal and two in total. Operator
// membership is the service's check; every refusal is a bounded 503.
type ProcessingHandler struct {
	sessions SessionHandler
	service  ProcessingChangeService
	slots    chan struct{}
	mu       sync.Mutex
	active   map[string]bool
}

func NewProcessingHandler(sessions SessionHandler, service ProcessingChangeService) (*ProcessingHandler, error) {
	if sessions.Sessions == nil || service == nil {
		return nil, errors.New("processing handler configuration")
	}
	return &ProcessingHandler{sessions: sessions, service: service, slots: make(chan struct{}, 2), active: map[string]bool{}}, nil
}

type processingChangeInput struct {
	Action           string                 `json:"action"`
	RuleID           string                 `json:"ruleID,omitempty"`
	ExpectedRevision int64                  `json:"expectedRevision,omitempty"`
	Scope            *value.ProcessingScope `json:"scope,omitempty"`
}

type processingChangeReply struct {
	RootID      string    `json:"rootID"`
	Epoch       string    `json:"epoch"`
	RequestID   string    `json:"requestID"`
	RuleID      string    `json:"ruleID,omitempty"`
	OperationID string    `json:"operationID"`
	State       string    `json:"state"`
	Revision    int64     `json:"revision"`
	Sequence    int64     `json:"sequence"`
	ObservedAt  time.Time `json:"observedAt"`
	ValidUntil  time.Time `json:"validUntil"`
}

func (h *ProcessingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.sessions.base(w, r) {
		return
	}
	if r.URL.Path != ProcessingChangesPath || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		sessionProblem(w, 404)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		sessionProblem(w, 405)
		return
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	key := r.Header.Get("Idempotency-Key")
	if err != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && params["charset"] != "utf-8" || len(r.Header.Values("Content-Encoding")) != 0 || len(r.Header.Values("Idempotency-Key")) != 1 || !authorization.UUID(key) {
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
	principal := ""
	defer func() {
		if principal != "" {
			h.mu.Lock()
			delete(h.active, principal)
			h.mu.Unlock()
		}
	}()
	// The change keeps its own original five-second bounds; this only caps
	// the request so a stalled body read cannot hold a slot.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	if controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		sessionProblem(w, 503)
		return
	}
	interrupted := make(chan struct{})
	var socketMu sync.Mutex
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		socketMu.Lock()
		defer socketMu.Unlock()
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	current, view, err := h.sessions.AuthenticateCurrent(w, r.WithContext(ctx))
	if err != nil {
		sessionFailure(w, err)
		return
	}
	account := view.Identity.Principal.Issuer + "\x00" + view.Identity.Principal.Subject
	h.mu.Lock()
	if h.active[account] {
		h.mu.Unlock()
		sessionProblem(w, 429)
		return
	}
	h.active[account] = true
	principal = account
	h.mu.Unlock()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	var in processingChangeInput
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err != nil || len(body) > 4096 || d.Decode(&in) != nil || d.More() {
		sessionProblem(w, 400)
		return
	}
	change := value.ProcessingChange{RequestID: key, RuleID: in.RuleID, Action: in.Action, ExpectedRevision: in.ExpectedRevision}
	if in.Scope != nil {
		change.Scope = *in.Scope
	}
	if !change.Valid() {
		sessionProblem(w, 400)
		return
	}
	receipt, err := h.service.Change(ctx, current, change)
	until := identity.Earlier(deadline, identity.Earlier(view.Identity.ValidUntil, receipt.ValidUntil))
	if err != nil || ctx.Err() != nil || !receipt.Valid(time.Now()) || !time.Now().Before(until) {
		sessionProblem(w, 503)
		return
	}
	// Change already performed its final current-authority read. Preserve
	// that receipt's original bound through the socket flush without a new
	// observation. Cancellation cannot be overwritten by a later deadline.
	socketMu.Lock()
	if ctx.Err() != nil || !time.Now().Before(until) {
		err = context.Canceled
	} else {
		err = controller.SetWriteDeadline(until)
	}
	socketMu.Unlock()
	if err != nil || ctx.Err() != nil || !time.Now().Before(until) {
		sessionProblem(w, 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(processingChangeReply{RootID: receipt.RootID, Epoch: receipt.Epoch, RequestID: receipt.RequestID, RuleID: receipt.RuleID, OperationID: receipt.OperationID,
		State: receipt.State, Revision: receipt.Revision, Sequence: receipt.Sequence, ObservedAt: receipt.ObservedAt, ValidUntil: receipt.ValidUntil})
	if err != nil || controller.Flush() != nil || ctx.Err() != nil || !time.Now().Before(until) {
		panic(http.ErrAbortHandler)
	}
}
