package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

// shortSession ends the browser session soon after the stream starts.
type shortSession struct {
	investigationSession
	expiresAt time.Time
}

func (s *shortSession) Resolve(ctx context.Context, cookie string, refresh bool) (identities.SessionView, error) {
	v, err := s.investigationSession.Resolve(ctx, cookie, refresh)
	v.ExpiresAt = s.expiresAt
	return v, err
}

func TestChangesDeliverOnlyWatchedIDsAndAnyChange(t *testing.T) {
	changes := presentation.NewChanges()
	s := changes.Subscribe([]string{"a"})
	defer s.Close()
	changes.Publish("b")
	select {
	case <-s.Ready():
		t.Fatal("signalled for an unwatched ID")
	default:
	}
	changes.Publish("a")
	changes.Publish("")
	<-s.Ready()
	if got := s.Take(); len(got) != 2 {
		t.Fatal("pending", got)
	}
}

func TestEventsStreamEndsAtSessionDeadline(t *testing.T) {
	var handler *EventsHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	calls := &investigationCalls{}
	ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{Clusters: localCluster, PublicOrigin: server.URL, CollectionEnabled: true, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, calls, calls)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewEventsHandler(SessionHandler{Origin: server.URL, Sessions: &shortSession{expiresAt: time.Now().Add(time.Second)}}, ops, presentation.NewChanges())
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest("GET", server.URL+EventsPath+"?capture_id=00000000-0000-4000-8000-000000000030", nil)
	if err != nil {
		t.Fatal(err)
	}
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

func TestEventsStreamPushesCaptureProgress(t *testing.T) {
	var handler *EventsHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	calls := &investigationCalls{}
	ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{Clusters: localCluster, PublicOrigin: server.URL, CollectionEnabled: true, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, calls, calls)
	if err != nil {
		t.Fatal(err)
	}
	changes := presentation.NewChanges()
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
	for _, query := range []string{"", "?capture_id=x", "?other_id=00000000-0000-4000-8000-000000000030", "?capture_id=00000000-0000-4000-8000-000000000030&capture_id=00000000-0000-4000-8000-000000000030"} {
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
	changes.Publish("00000000-0000-4000-8000-000000000031") // unwatched
	changes.Publish("00000000-0000-4000-8000-000000000030")
	if e := next(); e.Type != "capture" || e.Revision != 1 {
		t.Fatal("pushed state", e)
	}
	calls.hidden.Store(true)
	changes.Publish("00000000-0000-4000-8000-000000000030")
	if e := next(); e.Type != "accessLost" {
		t.Fatal("shown capture lost access", e)
	}

	// A capture that is not visible yet is awaited: an approval may start it.
	waiting := get("?capture_id=00000000-0000-4000-8000-000000000030")
	defer waiting.Body.Close()
	lines = bufio.NewScanner(waiting.Body)
	time.Sleep(50 * time.Millisecond)
	calls.hidden.Store(false)
	changes.Publish("00000000-0000-4000-8000-000000000030")
	if e := next(); e.Type != "capture" || e.ID != "00000000-0000-4000-8000-000000000030" {
		t.Fatal("awaited capture", e)
	}
	// A decision without a visible capture ends the wait, so the console
	// rereads the grant.
	calls.hidden.Store(true)
	decided := get("?capture_id=00000000-0000-4000-8000-000000000030")
	defer decided.Body.Close()
	lines = bufio.NewScanner(decided.Body)
	time.Sleep(50 * time.Millisecond)
	changes.Publish("00000000-0000-4000-8000-000000000030")
	if e := next(); e.Type != "accessLost" {
		t.Fatal("decision without a capture", e)
	}
}

func TestEventReadNamesTheStatusOperation(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000030"
	for kind, want := range map[string]string{"capture": `get_capture {"capture_id":"` + id + `"}`, "grant": `get_grant {"grant_id":"` + id + `"}`, "download": `download_artifact {"action":"status","download_id":"` + id + `"}`} {
		if name, input := eventRead(kind, id); name+" "+string(input) != want {
			t.Errorf("%s: %s %s", kind, name, input)
		}
	}
}
