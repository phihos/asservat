package agent

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/api"
)

// The agent reaches the hub from its own source ports, also with several
// connections at once, and captures leave those ports out.
func TestHubConnectionsLeaveFromTheAgentsPorts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	used := map[int]bool{}
	for range 3 {
		conn, err := DialHub(t.Context(), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		port := conn.LocalAddr().(*net.TCPAddr).Port
		if port < hubPortFirst || port > hubPortLast || used[port] {
			t.Fatal("source port", port, used)
		}
		used[port] = true
	}
	for filter, want := range map[string]string{
		"":                     "not (tcp portrange 61000-61063)",
		"tcp port 8080 or udp": "(tcp port 8080 or udp) and not (tcp portrange 61000-61063)",
	} {
		if got := withoutOwnTraffic(filter); got != want {
			t.Errorf("withoutOwnTraffic(%q) = %q, want %q", filter, got, want)
		}
	}
}

// An address that does not answer is given up after the wait, not after
// the two minutes the kernel tries for: the agent tries anew by itself.
func TestHubThatDoesNotAnswerIsGivenUp(t *testing.T) {
	began := time.Now()
	// An address for documentation (RFC 5737): nothing answers there.
	conn, err := dialHub(t.Context(), "tcp", "192.0.2.1:80", 300*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("connected to an address where nothing is")
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Fatal("given up only after", took)
	}
}

// A task's result reaches the hub though the hub is away when the task
// ends, as it is while it is upgraded: the agent reports again when its
// stream to the hub is back, without asking at intervals meanwhile. What
// the hub itself refuses is not reported again.
func TestResultIsReportedWhenTheHubIsBack(t *testing.T) {
	var mu sync.Mutex
	away, got, refuse := true, []string{}, false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case away:
			// The hub is not there: the connection ends without an answer.
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
		case refuse:
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		default:
			body, _ := io.ReadAll(r.Body)
			got = append(got, r.URL.Path+" "+string(body))
		}
	}))
	defer server.Close()
	a := &Agent{HubURL: server.URL, Token: "t", HTTP: server.Client()}
	a.connected = make(chan struct{})
	done := make(chan struct{})
	go func() {
		a.report(context.Background(), "capture-1", api.TaskStatus{Pod: "api-1", State: api.StateCompleted})
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("the result was given up while the hub was away")
	case <-time.After(300 * time.Millisecond):
	}
	mu.Lock()
	away = false
	mu.Unlock()
	a.reconnected()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the result was not reported when the hub was back")
	}
	if len(got) != 1 || !strings.Contains(got[0], "/agent/captures/capture-1/status") || !strings.Contains(got[0], `"Completed"`) {
		t.Fatal("the hub got:", got)
	}
	// A capture that the hub no longer knows: said once, and that is that.
	mu.Lock()
	refuse = true
	mu.Unlock()
	finished := make(chan struct{})
	go func() {
		a.report(context.Background(), "capture-2", api.TaskStatus{Pod: "api-1", State: api.StateCompleted})
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("a refused result is reported again and again")
	}
}
