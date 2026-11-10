package browser

import (
	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const ProcessingRulesPath = "/api/v1/processing/rules"

type ProcessingInventoryService interface {
	List(context.Context, app.CurrentIdentity, value.ProcessingInventoryQuery) (value.ProcessingInventoryPage, error)
}

type ProcessingInventoryHandler struct {
	sessions SessionHandler
	service  ProcessingInventoryService
	slots    chan struct{}
	mu       sync.Mutex
	active   map[string]bool
}

func NewProcessingInventoryHandler(sessions SessionHandler, service ProcessingInventoryService) (*ProcessingInventoryHandler, error) {
	if sessions.Sessions == nil || service == nil {
		return nil, errors.New("processing inventory handler configuration")
	}
	return &ProcessingInventoryHandler{sessions: sessions, service: service, slots: make(chan struct{}, 2), active: map[string]bool{}}, nil
}

type processingInventoryRuleReply struct {
	ID                  string              `json:"id"`
	Revision            int64               `json:"revision"`
	State               string              `json:"state"`
	Scope               processingScopeWire `json:"scope"`
	AdministrationUntil time.Time           `json:"administrationUntil"`
	RetireBy            time.Time           `json:"retireBy"`
}
type processingInventoryReply struct {
	RootID      string                         `json:"rootID"`
	Epoch       string                         `json:"epoch"`
	Initialized bool                           `json:"initialized"`
	Sequence    int64                          `json:"sequence"`
	Rules       []processingInventoryRuleReply `json:"rules"`
	NextCursor  string                         `json:"nextCursor,omitempty"`
	ObservedAt  time.Time                      `json:"observedAt"`
	ValidUntil  time.Time                      `json:"validUntil"`
}

func processingInventoryRequest(raw string) (value.ProcessingInventoryQuery, bool) {
	q := value.ProcessingInventoryQuery{Limit: 50}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return q, false
	}
	for name, v := range values {
		if len(v) != 1 {
			return q, false
		}
		switch name {
		case "after":
			q.After = v[0]
			if q.After == "" {
				return q, false
			}
		case "limit":
			q.Limit, err = strconv.Atoi(v[0])
			if err != nil {
				return q, false
			}
		default:
			return q, false
		}
	}
	return q, q.Valid()
}
func (h *ProcessingInventoryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.sessions.base(w, r) {
		return
	}
	if r.URL.Path != ProcessingRulesPath || r.URL.RawPath != "" {
		sessionProblem(w, 404)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		sessionProblem(w, 405)
		return
	}
	q, ok := processingInventoryRequest(r.URL.RawQuery)
	if !ok || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
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
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	if controller.SetWriteDeadline(deadline) != nil {
		sessionProblem(w, 503)
		return
	}
	var socketMu sync.Mutex
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		socketMu.Lock()
		defer socketMu.Unlock()
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
	h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.active, account); h.mu.Unlock() }()
	page, err := h.service.List(ctx, current, q)
	until := identity.Earlier(deadline, identity.Earlier(view.Identity.ValidUntil, page.ValidUntil))
	if err != nil || ctx.Err() != nil || !page.Valid(q, time.Now()) || !time.Now().Before(until) {
		sessionProblem(w, 503)
		return
	}
	out := processingInventoryReply{RootID: page.RootID, Epoch: page.Epoch, Initialized: page.Initialized, Sequence: page.Sequence, Rules: []processingInventoryRuleReply{}, NextCursor: page.NextCursor, ObservedAt: page.ObservedAt, ValidUntil: page.ValidUntil}
	for _, rule := range page.Rules {
		out.Rules = append(out.Rules, processingInventoryRuleReply{ID: rule.ID, Revision: rule.Revision, State: rule.State, Scope: processingScopeReply(rule.Scope), AdministrationUntil: rule.AdministrationUntil, RetireBy: rule.RetireBy})
	}
	body, err := json.Marshal(out)
	if err != nil || len(body) > 256<<10 {
		sessionProblem(w, 503)
		return
	}
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
	if _, err = w.Write(body); err != nil || controller.Flush() != nil || ctx.Err() != nil || !time.Now().Before(until) {
		panic(http.ErrAbortHandler)
	}
}
