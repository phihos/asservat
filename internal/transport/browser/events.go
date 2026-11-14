package browser

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/transport/presentation"
)

// EventsPath is the console's one status stream (REQ-INT-003).
const EventsPath = "/api/v1/events"

// ChangeSubscription delivers the IDs whose state changed since the last
// Take. An empty ID means anything may have changed (listener reconnect).
type ChangeSubscription interface {
	Ready() <-chan struct{}
	Take() map[string]struct{}
	Close()
}

// EventsHandler serves GET /api/v1/events as Server-Sent Events. Each event
// is the unchanged get_capture result, read through the same audited
// operation as a POST, so every event is authorized and audited like one
// status read. A denied read ends the stream with accessLost.
type EventsHandler struct {
	sessions   SessionHandler
	operations presentation.Operations
	captures   *Changes
	// Report receives fixed failure stages (diagnostics only).
	Report func(string)
}

func NewEventsHandler(sessions SessionHandler, operations presentation.Operations, captures *Changes) (*EventsHandler, error) {
	if sessions.Sessions == nil || !sessions.validOrigin() || operations == nil || captures == nil {
		return nil, presentation.ErrOperationsConfiguration
	}
	return &EventsHandler{sessions: sessions, operations: operations, captures: captures}, nil
}

type statusEvent struct {
	Type     string          `json:"type"`
	ID       string          `json:"id"`
	Revision int64           `json:"revision,omitempty"`
	Result   json.RawMessage `json:"result,omitempty"`
}

func (h *EventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.sessions.base(w, r) {
		return
	}
	if r.URL.Path != EventsPath || r.URL.RawPath != "" {
		sessionProblem(w, 404)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		sessionProblem(w, 405)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	ids := query["capture_id"]
	if err != nil || len(query) != 1 || len(ids) == 0 {
		sessionProblem(w, 400)
		return
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !authorization.UUID(id) || seen[id] {
			sessionProblem(w, 400)
			return
		}
		seen[id] = true
	}
	if _, _, err := h.sessions.AuthenticateCurrentWithin(w, r, 5*time.Second); err != nil {
		sessionFailure(w, err)
		return
	}
	subscription := h.captures.Subscribe()
	defer subscription.Close()
	control := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	if control.Flush() != nil {
		return
	}
	for _, id := range ids {
		if !h.send(w, r, control, id) {
			return
		}
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-subscription.Ready():
		}
		changed := subscription.Take()
		_, all := changed[""]
		for _, id := range ids {
			if _, ok := changed[id]; (all || ok) && !h.send(w, r, control, id) {
				return
			}
		}
	}
}

// send writes the current state of one capture; false ends the stream.
func (h *EventsHandler) send(w http.ResponseWriter, r *http.Request, control *http.ResponseController, id string) bool {
	ctx, cancel := context.WithTimeout(r.Context(), audit.OperationRequestWindow("get_capture"))
	defer cancel()
	request := r.WithContext(ctx)
	event := statusEvent{Type: "accessLost", ID: id}
	current, _, err := h.sessions.AuthenticateCurrentWithin(w, request, audit.OperationRequestWindow("get_capture"))
	if err == nil {
		input, _ := json.Marshal(map[string]string{"capture_id": id})
		out, callErr := h.operations.Call(ctx, current, "get_capture", input)
		defer func() { _ = out.Close(ctx); clear(out.Body) }()
		if callErr != nil || out.CheckDisclosure(ctx) != nil || !time.Now().Before(out.ValidUntil) {
			h.report("call")
			return false
		}
		var envelope struct {
			Status string `json:"status"`
			Data   struct {
				Revision int64 `json:"revision"`
			} `json:"data"`
		}
		if json.Unmarshal(out.Body, &envelope) != nil {
			h.report("result")
			return false
		}
		if envelope.Status == "ok" {
			event = statusEvent{Type: "capture", ID: id, Revision: envelope.Data.Revision, Result: out.Body}
		}
	}
	data, err := json.Marshal(event)
	if err != nil || control.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil {
		return false
	}
	frame := append(append(append([]byte("event: "+event.Type+"\ndata: "), data...), '\n'), '\n')
	if _, err = w.Write(frame); err != nil || control.Flush() != nil {
		return false
	}
	return event.Type != "accessLost"
}

func (h *EventsHandler) report(stage string) {
	if h.Report != nil {
		h.Report("events-" + stage)
	}
}
