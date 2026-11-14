package browser

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/transport/presentation"
)

func TestEventsStreamPushesCaptureProgress(t *testing.T) {
	var handler *EventsHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	calls := &investigationCalls{}
	ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, CollectionEnabled: true, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, calls, calls)
	if err != nil {
		t.Fatal(err)
	}
	changes := NewChanges()
	handler, err = NewEventsHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{}}, ops, changes)
	if err != nil {
		t.Fatal(err)
	}
	get := func(query string) *http.Response {
		r, e := http.NewRequest("GET", server.URL+EventsPath+query, nil)
		if e != nil {
			t.Fatal(e)
		}
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		response, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		return response
	}
	for _, query := range []string{"", "?capture_id=x", "?grant_id=00000000-0000-4000-8000-000000000030", "?capture_id=00000000-0000-4000-8000-000000000030&capture_id=00000000-0000-4000-8000-000000000030"} {
		if response := get(query); response.StatusCode != 400 {
			t.Fatal("accepted invalid query", query, response.StatusCode)
		}
	}
	response := get("?capture_id=00000000-0000-4000-8000-000000000030")
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/event-stream" || response.Header.Get("Cache-Control") != "no-store, private" {
		t.Fatal("stream", response.StatusCode, response.Header)
	}
	lines := bufio.NewScanner(response.Body)
	next := func() statusEvent {
		var event statusEvent
		for lines.Scan() {
			if data, ok := strings.CutPrefix(lines.Text(), "data: "); ok {
				if json.Unmarshal([]byte(data), &event) != nil {
					t.Fatal("event data", data)
				}
				return event
			}
		}
		t.Fatal("stream ended", lines.Err())
		return event
	}
	if e := next(); e.Type != "capture" || e.ID != "00000000-0000-4000-8000-000000000030" || e.Revision != 1 || !strings.Contains(string(e.Result), `"phase":"Pending"`) {
		t.Fatal("initial state", e)
	}
	changes.Publish("00000000-0000-4000-8000-000000000031")
	changes.Publish("00000000-0000-4000-8000-000000000030")
	if e := next(); e.Type != "capture" || e.Revision != 1 {
		t.Fatal("pushed state", e)
	}
}
