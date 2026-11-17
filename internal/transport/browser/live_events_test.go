package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/transport/presentation"
)

const liveWatch = "00000000-0000-4000-8000-000000000044"

// liveScript answers watch_live reads by cursor; it stands in for the
// audited operation set.
type liveScript struct {
	mu      sync.Mutex
	cursors []string
	answer  func(cursor string) string
}

func (*liveScript) PublicOrigin() string { return "https://console.invalid" }
func (*liveScript) ToolNames() []string  { return []string{"watch_live"} }
func (*liveScript) Tool(name string) (contracts.InvestigationTool, bool) {
	return contracts.InvestigationTool{}, name == "watch_live"
}
func (s *liveScript) Call(_ context.Context, _ identities.CurrentIdentity, name string, raw json.RawMessage) (presentation.OperationReply, error) {
	var in struct {
		Action, Cursor string
		WaitMS         int `json:"wait_ms"`
	}
	if name != "watch_live" || json.Unmarshal(raw, &in) != nil || in.Action != "read" || in.WaitMS != liveStreamWaitMS {
		return presentation.OperationReply{}, presentation.ErrOperationDelivery
	}
	s.mu.Lock()
	s.cursors = append(s.cursors, in.Cursor)
	s.mu.Unlock()
	return presentation.OperationReply{Body: []byte(s.answer(in.Cursor)), ValidUntil: time.Now().Add(time.Minute)}, nil
}

const liveHandlingJSON = `{"transient":true,"may_contain_user_data":true,"raw_available_live":false,"external_copies_recallable":false,"save_semantics":"freshCurrentWindow"}`

func liveOK(state, next string, rows, gaps int) string {
	r := make([]string, rows)
	for n := range r {
		r[n] = `{"row_id":"r` + string(rune('0'+n)) + `"}`
	}
	g := make([]string, gaps)
	for n := range g {
		g[n] = `{"reason":"sensorLoss","source_session_id":null,"count":null,"from":"2026-11-17T12:00:00Z","until":"2026-11-17T12:00:00Z"}`
	}
	cursor := "null"
	if next != "" {
		cursor = `"` + next + `"`
	}
	return `{"status":"ok","next_cursor":` + cursor + `,"data":{"watch_id":"` + liveWatch + `","revision":2,"state":"` + state + `","rows":[` + strings.Join(r, ",") + `],"sources":[],"gaps":[` + strings.Join(g, ",") + `],"output_bytes_spent":7,"handling":` + liveHandlingJSON + `}}`
}
func liveError(code string, retryable bool) string {
	b, _ := json.Marshal(map[string]any{"status": "error", "data": map[string]any{"code": code, "message": "m", "retryable": retryable}})
	return string(b)
}

type sse struct{ ID, Event, Data string }

func liveStream(t *testing.T, script *liveScript, last string) (int, []sse, string) {
	return liveStreamWith(t, script, last, nil)
}

func liveStreamWith(t *testing.T, script *liveScript, last string, now func() time.Time) (int, []sse, string) {
	t.Helper()
	var handler *LiveEventsHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	var err error
	handler, err = NewLiveEventsHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{}}, script)
	if err != nil {
		t.Fatal(err)
	}
	if now != nil {
		handler.now = now
	}
	r, _ := http.NewRequest("GET", server.URL+LiveEventsPrefix+liveWatch+LiveEventsSuffix, nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
	if last != "" {
		r.Header.Set("Last-Event-ID", last)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	response, err := server.Client().Do(r.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return response.StatusCode, nil, ""
	}
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal("stream did not end", err)
	}
	var events []sse
	var e sse
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if e != (sse{}) {
				events = append(events, e)
			}
			e = sse{}
		case strings.HasPrefix(line, "id: "):
			e.ID = line[4:]
		case strings.HasPrefix(line, "event: "):
			e.Event = line[7:]
		case strings.HasPrefix(line, "data: "):
			e.Data = line[6:]
		}
	}
	return 200, events, string(raw)
}

func TestLiveStreamStartsAtHeadAndEndsWithTheWatch(t *testing.T) {
	script := &liveScript{answer: func(c string) string {
		switch c {
		case "head":
			return liveOK("Active", "c1", 0, 0)
		case "c1":
			return liveOK("Active", "c2", 1, 1)
		}
		return liveOK("SourceEnded", "", 0, 0)
	}}
	_, events, _ := liveStream(t, script, "")
	got := []string{}
	for _, e := range events {
		got = append(got, e.Event+"@"+e.ID)
		var doc map[string]any
		if json.Unmarshal([]byte(e.Data), &doc) != nil || doc["event_id"] != e.ID || doc["type"] != e.Event || doc["watch_id"] != liveWatch || doc["handling"] == nil {
			t.Fatal("event document", e.Data)
		}
	}
	want := []string{"state@c1!0", "row@c1!1", "gap@c1!2", "state@c2!0", "state@c2!1"}
	if strings.Join(got, " ") != strings.Join(want, " ") || strings.Join(script.cursors, " ") != "head c1 c2" {
		t.Fatal(got, script.cursors)
	}
}

func TestLiveStreamResumesAfterLastEventID(t *testing.T) {
	script := &liveScript{answer: func(c string) string {
		if c == "c1" {
			return liveOK("Active", "c2", 1, 1)
		}
		return liveOK("Closed", "", 0, 0)
	}}
	_, events, _ := liveStream(t, script, "c1!1")
	if len(events) != 3 || events[0].Event != "gap" || events[0].ID != "c1!2" || script.cursors[0] != "c1" {
		t.Fatal("resume must reread the cursor and skip delivered events", events, script.cursors)
	}
	if status, _, _ := liveStream(t, script, "bad id"); status != 400 {
		t.Fatal("malformed Last-Event-ID accepted", status)
	}
}

func TestLiveStreamResyncsAtHeadAfterARevisionChange(t *testing.T) {
	script := &liveScript{answer: func(c string) string {
		switch c {
		case "old":
			return liveError("Conflict", false)
		case "head":
			return liveOK("Paused", "c9", 0, 1)
		}
		return liveOK("Closed", "", 0, 0)
	}}
	_, events, _ := liveStream(t, script, "old!0")
	if strings.Join(script.cursors, " ") != "old head c9" || len(events) < 2 || events[0].Event != "gap" {
		t.Fatal(script.cursors, events)
	}
}

func TestLiveStreamEndsOnAccessLossAndRetriesTemporaryMisses(t *testing.T) {
	script := &liveScript{answer: func(string) string { return liveError("LiveUnavailable", false) }}
	_, events, _ := liveStream(t, script, "")
	if len(events) != 1 || events[0].Event != "state" || !strings.Contains(events[0].Data, `"state":"AccessLost"`) {
		t.Fatal("access loss must end the stream with AccessLost", events)
	}
	script = &liveScript{answer: func(string) string { return liveError("LiveUnavailable", true) }}
	_, events, raw := liveStream(t, script, "")
	if len(events) != 0 || !strings.Contains(raw, "retry: 2000") || len(script.cursors) != 1 {
		t.Fatal("a temporary miss must hand reconnection to the browser", raw, script.cursors)
	}
}

func TestLiveStreamPathAndMethod(t *testing.T) {
	if _, ok := LiveWatchID(LiveEventsPrefix + "not-a-uuid" + LiveEventsSuffix); ok {
		t.Fatal("accepted a non-UUID watch")
	}
	if id, ok := LiveWatchID(LiveEventsPrefix + liveWatch + LiveEventsSuffix); !ok || id != liveWatch {
		t.Fatal("rejected a watch path")
	}
}

func TestLiveStreamEndsAtTheSessionDeadline(t *testing.T) {
	var handler *LiveEventsHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	script := &liveScript{answer: func(string) string { time.Sleep(50 * time.Millisecond); return liveOK("Active", "c1", 0, 0) }}
	var err error
	handler, err = NewLiveEventsHandler(SessionHandler{Origin: server.URL, Sessions: &shortSession{expiresAt: time.Now().Add(time.Second)}}, script)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("GET", server.URL+LiveEventsPrefix+liveWatch+LiveEventsSuffix, nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	done := make(chan error, 1)
	go func() { _, e := io.ReadAll(response.Body); done <- e }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream outlived the session")
	}
}

func TestLiveStreamNeverWritesPastTheReadDeadline(t *testing.T) {
	// The reply is current when the read returns and lapses before framing:
	// no event of that read may be written.
	var mu sync.Mutex
	checks := 0
	script := &liveScript{answer: func(string) string {
		mu.Lock()
		checks = 0
		mu.Unlock()
		return liveOK("Active", "c1", 1, 0)
	}}
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		checks++
		if checks > 1 {
			return time.Now().Add(time.Hour)
		}
		return time.Now()
	}
	_, events, raw := liveStreamWith(t, script, "", now)
	if len(events) != 0 || len(script.cursors) != 1 {
		t.Fatal("events written after the read's deadline", raw)
	}
}
