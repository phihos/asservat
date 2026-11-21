package browser

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

// LiveEventsPrefix and LiveEventsSuffix frame GET
// /api/v1/live/watches/{watch_id}/events (stream_live_watch).
const (
	LiveEventsPrefix = "/api/v1/live/watches/"
	LiveEventsSuffix = "/events"
)

// liveStreamWaitMS is each read's wait for rows. It stays well inside the
// twenty-second evidence request window, so a read that finds nothing returns
// an empty batch instead of hitting the request deadline.
const liveStreamWaitMS = 10000

// LiveEventsHandler streams one live watch as Server-Sent Events. Every batch
// is a watch_live read through the same audited operation as a POST, so each
// delivery is authorized, charged and audited like one read; node pushes end
// each read's wait. The stream ends with the watch, the session or a refusal;
// closing it leaves the watch open. It never renews the watch's hard end.
//
// An event ID is "<cursor>!<n>": a reconnect rereads that cursor and skips
// its first n events. The service replays a cursor inside its replay buffer;
// an older one resumes at the head with a bufferExpired gap.
type LiveEventsHandler struct {
	sessions   SessionHandler
	operations presentation.Operations
	// Report receives fixed failure stages (diagnostics only).
	Report func(string)
	now    func() time.Time
}

// delivery keeps one read's reply owned until its events are flushed; every
// write is checked against and bounded by the reply's original deadline.
type delivery struct {
	ctx   context.Context
	out   presentation.OperationReply
	until time.Time
	done  func()
}

func NewLiveEventsHandler(sessions SessionHandler, operations presentation.Operations) (*LiveEventsHandler, error) {
	if sessions.Sessions == nil || !sessions.validOrigin() || operations == nil {
		return nil, presentation.ErrOperationsConfiguration
	}
	return &LiveEventsHandler{sessions: sessions, operations: operations, now: time.Now}, nil
}

// liveEvent is one live-watch.schema.json#/$defs/event document.
type liveEvent struct {
	EventID  string          `json:"event_id"`
	WatchID  string          `json:"watch_id"`
	Revision int64           `json:"revision"`
	Type     string          `json:"type"`
	Row      json.RawMessage `json:"row,omitempty"`
	Gap      json.RawMessage `json:"gap,omitempty"`
	State    *liveState      `json:"state,omitempty"`
	Handling json.RawMessage `json:"handling"`
}
type liveState struct {
	State   string          `json:"state"`
	Sources json.RawMessage `json:"sources"`
	Spent   int64           `json:"output_bytes_spent"`
}
type liveBatch struct {
	WatchID  string            `json:"watch_id"`
	Revision int64             `json:"revision"`
	State    string            `json:"state"`
	Rows     []json.RawMessage `json:"rows"`
	Sources  json.RawMessage   `json:"sources"`
	Gaps     []json.RawMessage `json:"gaps"`
	Spent    int64             `json:"output_bytes_spent"`
	Handling json.RawMessage   `json:"handling"`
}

// LiveWatchID returns the watch ID of a stream path.
func LiveWatchID(path string) (string, bool) {
	id, ok := strings.CutPrefix(path, LiveEventsPrefix)
	if !ok {
		return "", false
	}
	id, ok = strings.CutSuffix(id, LiveEventsSuffix)
	return id, ok && authorization.UUID(id)
}

func (h *LiveEventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.sessions.base(w, r) {
		return
	}
	watch, ok := LiveWatchID(r.URL.Path)
	if !ok || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		sessionProblem(w, 404)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		sessionProblem(w, 405)
		return
	}
	if _, ok := h.operations.Tool("watch_live"); !ok {
		sessionProblem(w, 404)
		return
	}
	cursor, skip := resumePoint(r.Header.Get("Last-Event-ID"))
	if cursor == "" {
		sessionProblem(w, 400)
		return
	}
	_, view, err := h.sessions.AuthenticateCurrentWithin(w, r, 5*time.Second)
	if err != nil {
		sessionFailure(w, err)
		return
	}
	control := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if control.Flush() != nil {
		return
	}
	// One revision change (pause, filter) invalidates the cursor; the stream
	// then resyncs at the head once. A second conflict in a row ends it.
	resynced := false
	revision := int64(1)
	for r.Context().Err() == nil && h.now().Before(view.ExpiresAt) {
		batch, next, failure, d := h.read(w, r, watch, cursor)
		switch failure {
		case "":
		case "Conflict":
			if resynced || cursor == "head" {
				h.end(w, control, watch, revision, "AccessLost")
				return
			}
			cursor, skip, resynced = "head", 0, true
			continue
		case "retry":
			// A temporary miss: the browser reconnects with Last-Event-ID.
			_ = h.write(w, control, []byte("retry: 2000\n\n"), nil)
			return
		case "transport":
			return
		default:
			h.end(w, control, watch, revision, "AccessLost")
			return
		}
		resynced, revision = false, max(batch.Revision, 1)
		events := batchEvents(batch)
		for n := range events {
			events[n].EventID = cursor + "!" + strconv.Itoa(n+1)
			if n == len(events)-1 && next != "" {
				events[n].EventID = next + "!0"
			}
		}
		if skip > len(events) {
			skip = len(events)
		}
		sent := true
		for _, e := range events[skip:] {
			if sent = h.send(w, control, e, d); !sent {
				break
			}
		}
		d.done()
		if !sent {
			return
		}
		skip = 0
		if next == "" || batch.State != "Active" && batch.State != "Paused" && batch.State != "Disconnected" {
			return
		}
		cursor = next
	}
}

// resumePoint parses a Last-Event-ID; none starts at the head.
func resumePoint(last string) (string, int) {
	if last == "" {
		return "head", 0
	}
	cursor, raw, ok := strings.Cut(last, "!")
	n, err := strconv.Atoi(raw)
	if !ok || err != nil || n < 0 || strconv.Itoa(n) != raw || cursor == "" || len(cursor) > 4096 || !identity.Text(cursor, 4096) {
		return "", 0
	}
	return cursor, n
}

// read performs one audited watch_live read. failure is "" on success, the
// error code of a refusal, "retry" for a retryable refusal, or "transport".
func (h *LiveEventsHandler) read(w http.ResponseWriter, r *http.Request, watch, cursor string) (liveBatch, string, string, *delivery) {
	window := audit.OperationRequestWindow("watch_live")
	ctx, cancel := context.WithTimeout(r.Context(), window)
	current, _, err := h.sessions.AuthenticateCurrentWithin(w, r.WithContext(ctx), window)
	if err != nil {
		cancel()
		return liveBatch{}, "", "NotAuthorized", nil
	}
	input, _ := json.Marshal(map[string]any{"action": "read", "watch_id": watch, "cursor": cursor, "wait_ms": liveStreamWaitMS})
	out, err := h.operations.Call(ctx, current, "watch_live", input)
	responseCtx, stop := out.ResponseContext(ctx)
	d := &delivery{ctx: responseCtx, out: out, until: out.ValidUntil, done: func() { _ = out.Close(ctx); clear(out.Body); stop(); cancel() }}
	if end, ok := ctx.Deadline(); ok && end.Before(d.until) {
		d.until = end
	}
	fail := func(stage, failure string) (liveBatch, string, string, *delivery) {
		if stage != "" {
			h.report(stage)
		}
		d.done()
		return liveBatch{}, "", failure, nil
	}
	if err != nil || out.CheckDisclosure(responseCtx) != nil || !h.now().Before(d.until) {
		return fail("call", "transport")
	}
	var envelope struct {
		Status     string          `json:"status"`
		NextCursor *string         `json:"next_cursor"`
		Data       json.RawMessage `json:"data"`
	}
	if json.Unmarshal(out.Body, &envelope) != nil {
		return fail("result", "transport")
	}
	if envelope.Status != "ok" {
		var failure struct {
			Code      string `json:"code"`
			Retryable bool   `json:"retryable"`
		}
		_ = json.Unmarshal(envelope.Data, &failure)
		if failure.Retryable {
			return fail("", "retry")
		}
		return fail("", failure.Code)
	}
	var batch liveBatch
	if json.Unmarshal(envelope.Data, &batch) != nil || batch.WatchID != watch {
		return fail("batch", "transport")
	}
	next := ""
	if envelope.NextCursor != nil {
		next = *envelope.NextCursor
	}
	return batch, next, "", d
}

// batchEvents orders a batch as rows, gaps and one closing state event.
func batchEvents(b liveBatch) []liveEvent {
	events := make([]liveEvent, 0, len(b.Rows)+len(b.Gaps)+1)
	for _, row := range b.Rows {
		events = append(events, liveEvent{WatchID: b.WatchID, Revision: b.Revision, Type: "row", Row: row, Handling: b.Handling})
	}
	for _, gap := range b.Gaps {
		events = append(events, liveEvent{WatchID: b.WatchID, Revision: b.Revision, Type: "gap", Gap: gap, Handling: b.Handling})
	}
	sources := b.Sources
	if len(sources) == 0 {
		sources = json.RawMessage("[]")
	}
	return append(events, liveEvent{WatchID: b.WatchID, Revision: b.Revision, Type: "state", State: &liveState{State: b.State, Sources: sources, Spent: b.Spent}, Handling: b.Handling})
}

var liveHandling = json.RawMessage(`{"transient":true,"may_contain_user_data":true,"raw_available_live":false,"external_copies_recallable":false,"save_semantics":"freshCurrentWindow"}`)

// end sends a closing state event without disclosing anything new.
func (h *LiveEventsHandler) end(w http.ResponseWriter, control *http.ResponseController, watch string, revision int64, state string) {
	_ = h.send(w, control, liveEvent{EventID: "end!0", WatchID: watch, Revision: revision, Type: "state", State: &liveState{State: state, Sources: json.RawMessage("[]")}, Handling: liveHandling}, nil)
}

// send writes one event. A disclosing event (d set) is written only while its
// read's reply is current, and its write deadline never passes that reply's.
func (h *LiveEventsHandler) send(w http.ResponseWriter, control *http.ResponseController, e liveEvent, d *delivery) bool {
	data, err := json.Marshal(e)
	if err != nil {
		return false
	}
	frame := append([]byte("id: "+e.EventID+"\nevent: "+e.Type+"\ndata: "), data...)
	return h.write(w, control, append(frame, '\n', '\n'), d)
}

func (h *LiveEventsHandler) write(w http.ResponseWriter, control *http.ResponseController, frame []byte, d *delivery) bool {
	deadline := h.now().Add(10 * time.Second)
	if d != nil {
		if d.ctx.Err() != nil || d.out.CheckDisclosure(d.ctx) != nil || !h.now().Before(d.until) {
			return false
		}
		if d.until.Before(deadline) {
			deadline = d.until
		}
	}
	if control.SetWriteDeadline(deadline) != nil {
		return false
	}
	_, err := w.Write(frame)
	return err == nil && control.Flush() == nil
}

func (h *LiveEventsHandler) report(stage string) {
	if h.Report != nil {
		h.Report("live-events-" + stage)
	}
}
