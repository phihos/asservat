package browser

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

type processingService struct {
	changes []value.ProcessingChange
	err     error
	until   time.Time
	after   func()
}

func (s *processingService) Change(ctx context.Context, current identities.CurrentIdentity, c value.ProcessingChange) (value.ProcessingReceipt, error) {
	if _, err := current.ResolveIdentity(ctx); err != nil {
		return value.ProcessingReceipt{}, err
	}
	s.changes = append(s.changes, c)
	if s.err != nil {
		return value.ProcessingReceipt{}, s.err
	}
	now := time.Now().UTC()
	until := s.until
	if until.IsZero() {
		until = now.Add(5 * time.Second)
	}
	if s.after != nil {
		s.after()
	}
	return value.ProcessingReceipt{RootID: "00000000-0000-4000-8000-000000000041", Epoch: "00000000-0000-4000-8000-000000000042", RequestID: c.RequestID,
		OperationID: "00000000-0000-4000-8000-000000000043", State: "initialized", Sequence: 2, ObservedAt: now, ValidUntil: until}, nil
}

// ADR-210: the route needs the session, CSRF and one UUID Idempotency-Key,
// which becomes the change's request ID; it forwards only the change fields
// and answers every service refusal with 503.
func TestProcessingChangeRoute(t *testing.T) {
	var handler *ProcessingHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	service := &processingService{}
	var err error
	handler, err = NewProcessingHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{}}, service)
	if err != nil {
		t.Fatal(err)
	}
	const key = "00000000-0000-4000-8000-000000000044"
	send := func(body string, header func(*http.Request)) (int, string) {
		r, _ := http.NewRequest("POST", server.URL+ProcessingChangesPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", server.URL)
		r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
		r.Header.Set("Idempotency-Key", key)
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		if header != nil {
			header(r)
		}
		response, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		b, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(b)
	}
	body := `{"action":"initialize_processing"}`
	status, reply := send(body, nil)
	var out map[string]any
	if status != http.StatusOK || json.Unmarshal([]byte(reply), &out) != nil || out["state"] != "initialized" || out["requestID"] != key || len(service.changes) != 1 || service.changes[0].RequestID != key || service.changes[0].Action != "initialize_processing" {
		t.Fatal("initialization reply", status, reply)
	}
	for name, mutate := range map[string]func(*http.Request){
		"missing CSRF":   func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"missing key":    func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"non-UUID key":   func(r *http.Request) { r.Header.Set("Idempotency-Key", "operator-key-0123456789") },
		"two keys":       func(r *http.Request) { r.Header.Add("Idempotency-Key", key) },
		"foreign origin": func(r *http.Request) { r.Header.Set("Origin", "https://attacker.invalid") },
		"text body":      func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
	} {
		if status, _ := send(body, mutate); status < 400 {
			t.Fatal("request accepted without", name, status)
		}
	}
	for _, bad := range []string{`{"action":"initialize_processing","requestID":"chosen"}`, `{"action":"delete_everything"}`, `{"action":"restrict_processing"}`} {
		if status, _ := send(bad, nil); status != http.StatusBadRequest {
			t.Fatal("invalid change accepted", bad, status)
		}
	}
	service.err = value.ErrUnavailable
	if status, _ := send(body, nil); status != http.StatusServiceUnavailable {
		t.Fatal("refusal not mapped to 503", status)
	}
	if len(service.changes) != 2 {
		t.Fatal("refused requests reached the service", len(service.changes))
	}
}

type processingObservedBody struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (b *processingObservedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	return b.ReadCloser.Read(p)
}

func stalledProcessingConnection(t *testing.T, server *httptest.Server) *tls.Conn {
	t.Helper()
	target, _ := url.Parse(server.URL)
	connection, err := tls.Dial("tcp", target.Host, server.Client().Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	_, err = fmt.Fprintf(connection, "POST %s HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nContent-Type: application/json\r\nContent-Length: 128\r\nCookie: %s=%s\r\nX-CSRF-Token: %s\r\nIdempotency-Key: 00000000-0000-4000-8000-000000000044\r\n\r\n{",
		ProcessingChangesPath, target.Host, server.URL, SessionCookie, strings.Repeat("A", 43), strings.Repeat("C", 43))
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	return connection
}

type processingBlockedDeadline struct {
	http.ResponseWriter
	entered, release chan struct{}
	reads            atomic.Int32
}

func (w *processingBlockedDeadline) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *processingBlockedDeadline) SetReadDeadline(until time.Time) error {
	err := http.NewResponseController(w.ResponseWriter).SetReadDeadline(until)
	if w.reads.Add(1) > 1 {
		close(w.entered)
		<-w.release
	}
	return err
}

// Exercise the real TLS socket: cancelling a context alone does not interrupt
// a blocked request-body Read. The handler must stop the I/O before releasing
// its slot; the original parent deadline must also remain effective.
func TestProcessingChangeStalledBodyReleasesSlot(t *testing.T) {
	for _, mode := range []string{"deadline", "cancellation", "joined-cancellation"} {
		t.Run(mode, func(t *testing.T) {
			var handler *ProcessingHandler
			started, finished := make(chan struct{}), make(chan struct{})
			callback, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			cancelRequest := make(chan context.CancelFunc, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithCancel(r.Context())
				if mode == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(r.Context(), 200*time.Millisecond)
				}
				defer cancel()
				cancelRequest <- cancel
				r.Body = &processingObservedBody{ReadCloser: r.Body, started: started}
				if mode == "joined-cancellation" {
					w = &processingBlockedDeadline{ResponseWriter: w, entered: callback, release: release}
				}
				handler.ServeHTTP(w, r.WithContext(ctx))
				close(finished)
			}))
			defer server.Close()
			defer unblock()
			service := &processingService{}
			var err error
			handler, err = NewProcessingHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{}}, service)
			if err != nil {
				t.Fatal(err)
			}
			connection := stalledProcessingConnection(t, server)
			defer connection.Close()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("request never reached its body read")
			}
			cancel := <-cancelRequest
			if mode != "deadline" {
				cancel()
			}
			if mode == "joined-cancellation" {
				select {
				case <-callback:
				case <-time.After(time.Second):
					t.Fatal("cancellation did not interrupt the socket")
				}
				select {
				case <-finished:
					t.Fatal("handler returned while its cancellation callback could still change the connection")
				case <-time.After(25 * time.Millisecond):
				}
				if len(handler.slots) != 1 {
					t.Fatal("handler released its slot before joining cancellation")
				}
				handler.mu.Lock()
				heldPrincipals := len(handler.active)
				handler.mu.Unlock()
				if heldPrincipals != 1 {
					t.Fatal("handler released its principal before joining cancellation")
				}
				unblock()
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("stalled body retained the processing slot after its request ended")
			}
			if len(handler.slots) != 0 || len(service.changes) != 0 {
				t.Fatal("cancelled body retained capacity or reached the service", len(handler.slots), len(service.changes))
			}
		})
	}
}

func completeProcessingRequest(t *testing.T, server *httptest.Server) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, server.URL+ProcessingChangesPath, strings.NewReader(`{"action":"initialize_processing"}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", server.URL)
	r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
	r.Header.Set("Idempotency-Key", "00000000-0000-4000-8000-000000000044")
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
	return r
}

func TestProcessingChangeStalledBodyOwnsPrincipal(t *testing.T) {
	var handler *ProcessingHandler
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength == 128 {
			r.Body = &processingObservedBody{ReadCloser: r.Body, started: started}
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	service := &processingService{}
	var err error
	handler, err = NewProcessingHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{}}, service)
	if err != nil {
		t.Fatal(err)
	}
	connection := stalledProcessingConnection(t, server)
	defer connection.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first request did not reach its body read")
	}
	client := server.Client()
	client.Timeout = time.Second
	response, err := client.Do(completeProcessingRequest(t, server))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatal("same principal admitted a second request while the first body stalled", response.StatusCode)
	}
	if len(service.changes) != 0 {
		t.Fatal("duplicate request reached the processing service")
	}
}

type processingWriteDeadline struct {
	http.ResponseWriter
	until time.Time
}

func (w *processingWriteDeadline) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *processingWriteDeadline) SetWriteDeadline(until time.Time) error {
	w.until = until
	return http.NewResponseController(w.ResponseWriter).SetWriteDeadline(until)
}

func TestProcessingChangeReceiptKeepsOriginalWriteBound(t *testing.T) {
	for _, mode := range []string{"receipt", "session", "expired", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			var handler *ProcessingHandler
			written := make(chan time.Time, 1)
			service := &processingService{}
			sessions := &investigationSession{}
			wantUntil := time.Now().Add(time.Second).UTC()
			service.until = wantUntil
			if mode == "session" {
				sessions.finalUntil = wantUntil
				service.until = wantUntil.Add(time.Second)
			}
			if mode == "expired" {
				service.until = time.Now().Add(-time.Second)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				if mode == "cancelled" {
					service.after = cancel
				}
				bounded := &processingWriteDeadline{ResponseWriter: w}
				handler.ServeHTTP(bounded, r.WithContext(ctx))
				written <- bounded.until
			}))
			defer server.Close()
			var err error
			handler, err = NewProcessingHandler(SessionHandler{Origin: server.URL, Sessions: sessions}, service)
			if err != nil {
				t.Fatal(err)
			}
			response, err := server.Client().Do(completeProcessingRequest(t, server))
			if mode == "cancelled" && err != nil {
				return // Cancellation may abort the HTTP response entirely.
			}
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if mode == "expired" || mode == "cancelled" {
				if response.StatusCode == http.StatusOK {
					t.Fatal("expired or cancelled receipt reported success")
				}
				return
			}
			if response.StatusCode != http.StatusOK {
				t.Fatal("current receipt refused", response.StatusCode)
			}
			select {
			case until := <-written:
				if !until.Equal(wantUntil) {
					t.Fatal("receipt or original session write bound was not preserved", until, wantUntil)
				}
			case <-time.After(time.Second):
				t.Fatal("handler did not finish its response")
			}
		})
	}
}
