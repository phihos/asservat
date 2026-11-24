package agent

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	// A proxy that answers for a hub that is away is waited out as well; a
	// hub that is there and fails is not, since no reconnection would follow.
	for status, again := range map[int]bool{http.StatusServiceUnavailable: true, http.StatusBadGateway: true, http.StatusInternalServerError: false} {
		asked := make(chan struct{}, 4)
		answering := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			asked <- struct{}{}
			w.WriteHeader(status)
		}))
		b := &Agent{HubURL: answering.URL, Token: "t", HTTP: answering.Client()}
		b.connected = make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		ended := make(chan struct{})
		go func() {
			b.report(ctx, "capture-3", api.TaskStatus{Pod: "api-1", State: api.StateCompleted})
			close(ended)
		}()
		<-asked
		select {
		case <-ended:
			if again {
				t.Errorf("the result was given up at status %d", status)
			}
		case <-time.After(300 * time.Millisecond):
			if !again {
				t.Errorf("the agent waits for a hub that answered with status %d", status)
			}
			b.reconnected()
			<-asked // reported again once the stream is back
		}
		cancel()
		<-ended
		answering.Close()
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

// A file that rests on the node, as a core does, is uploaded again from its
// beginning when the hub was away for the first try: a crashed process
// leaves its core once. What comes from a running tool is sent once.
func TestFileIsUploadedWhenTheHubIsBack(t *testing.T) {
	var mu sync.Mutex
	away, got := true, map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if away {
			io.CopyN(io.Discard, r.Body, 4) // some of the file is on its way
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		body, _ := io.ReadAll(r.Body)
		got[r.URL.Path] = string(body)
	}))
	defer server.Close()
	a := &Agent{HubURL: server.URL, Token: "t", HTTP: server.Client()}
	a.connected = make(chan struct{})
	core := filepath.Join(t.TempDir(), "core")
	os.WriteFile(core, []byte("a synthetic core"), 0o600)
	f, err := os.Open(core)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	done := make(chan error, 1)
	go func() { done <- a.upload(context.Background(), "capture-1", "api-1", "core.app", f) }()
	select {
	case err := <-done:
		t.Fatal("the upload was given up while the hub was away:", err)
	case <-time.After(300 * time.Millisecond):
	}
	mu.Lock()
	away = false
	mu.Unlock()
	a.reconnected()
	if err := <-done; err != nil || got["/agent/captures/capture-1/artifacts/api-1/core.app"] != "a synthetic core" {
		t.Fatal("the file after the hub was back:", err, got)
	}
	// A tool's output cannot be read again: its upload fails as before.
	mu.Lock()
	away = true
	mu.Unlock()
	if err := a.upload(context.Background(), "capture-1", "api-1", "capture.pcap", io.MultiReader(strings.NewReader("packets"))); err == nil {
		t.Fatal("a stream was uploaded to a hub that is away")
	}
}
