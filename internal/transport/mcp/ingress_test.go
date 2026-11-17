package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

// Test-only recorder of the wrapper's call rows. It proves transport
// composition, not SQL audit storage.
type ingressAuditFixture struct {
	mu       sync.Mutex
	events   []audit.Event
	onRecord func(context.Context)
	err      error
}

func (f *ingressAuditFixture) Record(ctx context.Context, e audit.Event) error {
	f.mu.Lock()
	f.events = append(f.events, e)
	f.mu.Unlock()
	if f.onRecord != nil {
		f.onRecord(ctx)
	}
	return f.err
}
func (f *ingressAuditFixture) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}
func auditedMCPFixture(t *testing.T) (*Handler, *httptest.Server, *mcpCaptureFixture, *ingressAuditFixture, *atomic.Bool) {
	t.Helper()
	var h *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	capture := &mcpCaptureFixture{}
	ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, CollectionEnabled: true, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, capture, capture)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := presentation.NewInvestigationOperations(ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := auditapp.NewOperationMAC("audit-v1", bytes.Repeat([]byte{1}, 32), "accounts-v1", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mac.Close)
	recorder := &ingressAuditFixture{}
	var sequence atomic.Uint64
	audited, err := presentation.NewAuditedOperations(presentation.AuditedOperationsConfig{RootID: "00000000-0000-4000-8000-000000000010", Now: time.Now, NewID: func() string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", sequence.Add(1)) }}, inner, recorder, mac)
	if err != nil {
		t.Fatal(err)
	}
	denied := &atomic.Bool{}
	h, err = NewAuditedContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
		i := testIdentity()
		i.Scopes = append(i.Scopes, "evidence:capture")
		if denied.Load() {
			i.Scopes = nil
		}
		return i, nil
	}), audited)
	if err != nil {
		t.Fatal(err)
	}
	return h, server, capture, recorder, denied
}
func TestAuditedMCPIngressRejectsOnceBeforeDispatchAcrossRevisions(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		for _, mode := range []string{"unknown", "schema", "scope", "sdk-params", "sdk-meta", "request-state", "missing-id", "null-id", "object-id", "oversized-name"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				_, server, capture, rows, denied := auditedMCPFixture(t)
				params := map[string]any{"name": "request_capture", "arguments": mcpCaptureRequest()}
				switch mode {
				case "unknown":
					params["name"] = "private-user-input"
				case "schema":
					params["arguments"] = map[string]any{"private-user-input": "x"}
				case "scope":
					denied.Store(true)
				case "sdk-params":
					params["requestState"] = 42
				case "request-state":
					params["requestState"] = "private-user-input"
				case "oversized-name":
					params["name"] = strings.Repeat("x", 9000)
				}
				req := rpcRequest(t, server, version, "tools/call", params)
				if mode == "sdk-meta" || mode == "missing-id" || mode == "null-id" || mode == "object-id" {
					raw, _ := io.ReadAll(req.Body)
					var frame map[string]any
					_ = json.Unmarshal(raw, &frame)
					switch mode {
					case "sdk-meta":
						frame["params"].(map[string]any)["_meta"] = "private-user-input"
					case "missing-id":
						delete(frame, "id")
					case "null-id":
						frame["id"] = nil
					case "object-id":
						frame["id"] = map[string]any{"private-user-input": true}
					}
					raw, _ = json.Marshal(frame)
					req.Body = io.NopCloser(bytes.NewReader(raw))
					req.ContentLength = int64(len(raw))
				}
				response, body := send(t, server, req)
				if n := rows.count(); n != 1 || capture.calls.Load() != 0 {
					t.Fatalf("not exactly one rejection row: rows=%d effects=%d status=%d body=%s", n, capture.calls.Load(), response.StatusCode, body)
				}
				if rows.events[0].Operation != "invalid_operation" || rows.events[0].Effect != "none" || bytes.Contains(body, []byte("private-user-input")) || len(body) > MaxResponseBytes {
					t.Fatalf("rejection leaked/dispatched: %s", body)
				}
				if mode == "scope" && rows.events[0].Status != "denied" {
					t.Fatal("scope misclassified")
				}
			})
		}
	}
}
func TestAuditedMCPValidCallsHaveOneOwnerAndProtocolIsNotAnOperation(t *testing.T) {
	_, server, capture, rows, _ := auditedMCPFixture(t)
	for _, method := range []string{"initialize", "tools/list", "ping"} {
		params := map[string]any{}
		if method == "initialize" {
			params = map[string]any{"protocolVersion": "2025-11-25", "clientInfo": map[string]any{"name": "test", "version": "1"}, "capabilities": map[string]any{}}
		}
		send(t, server, rpcRequest(t, server, "2025-11-25", method, params))
	}
	if rows.count() != 0 {
		t.Fatal("handshake/list consumed audit")
	}
	for name, args := range map[string]any{"request_capture": mcpCaptureRequest(), "get_capture": map[string]any{"capture_id": "00000000-0000-4000-8000-000000000030"}} {
		response, b := send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": name, "arguments": args}))
		if response.StatusCode != 200 || bytes.Contains(b, []byte(`"error"`)) {
			t.Fatalf("valid call rejected %d %s", response.StatusCode, b)
		}
	}
	if n := rows.count(); n != 2 || capture.calls.Load() != 1 {
		t.Fatal("duplicate audit or dispatch", n, capture.calls.Load())
	}
}
func TestAuditedMCPUnavailableAuditBlocksEffectsAndCountsBoundedly(t *testing.T) {
	h, server, capture, rows, _ := auditedMCPFixture(t)
	rows.err = errors.New("private provider error")
	response, b := send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": "unknown", "arguments": map[string]any{}}))
	if response.StatusCode != 503 || capture.calls.Load() != 0 || bytes.Contains(b, []byte("private")) || h.SecurityCounters().AuditUnavailable != 1 {
		t.Fatalf("failed audit escaped %d %s %#v", response.StatusCode, b, h.SecurityCounters())
	}
}
func TestAuditedMCPOriginalHTTPCancellationReachesBothRevisions(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			_, server, capture, _, _ := auditedMCPFixture(t)
			entered, observed := make(chan struct{}), make(chan struct{})
			capture.during = func(ctx context.Context) { close(entered); <-ctx.Done(); close(observed) }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			req := rpcRequest(t, server, version, "tools/call", map[string]any{"name": "request_capture", "arguments": mcpCaptureRequest()}).WithContext(ctx)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				response, _ := server.Client().Do(req)
				if response != nil {
					response.Body.Close()
				}
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("audit not entered")
			}
			cancel()
			select {
			case <-observed:
			case <-time.After(time.Second):
				t.Fatal("SDK detached original HTTP cancellation")
			}
			<-finished
			if capture.calls.Load() != 0 {
				t.Fatal("canceled request dispatched")
			}
		})
	}
}
func TestMCPAttemptCASPreventsLateDispatchAndAuditDuplication(t *testing.T) {
	for _, cancelFirst := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		a := &operationAttempt{owner: ctx}
		if cancelFirst {
			cancel()
		}
		var winners atomic.Int64
		var wg sync.WaitGroup
		for i := range 32 {
			wg.Go(func() {
				kind := attemptDispatched
				if i%2 == 0 {
					kind = attemptRejected
				}
				if a.claim(kind) {
					winners.Add(1)
				}
			})
		}
		wg.Wait()
		cancel()
		a.close()
		want := int64(1)
		if cancelFirst {
			want = 0
		}
		if winners.Load() != want || a.claim(attemptDispatched) {
			t.Fatal("multiple/late invocation owners")
		}
	}
}

// Explicit identity fake tests the transport's own bound independently of the
// production CurrentIdentity's additional original-request lifetime fence.
type finalRejectionIdentity struct {
	until time.Time
	calls int
	late  bool
}

func (f *finalRejectionIdentity) ResolveIdentity(context.Context) (identity.Identity, error) {
	f.calls++
	if f.late && f.calls == 2 {
		<-time.After(time.Until(f.until.Add(time.Millisecond)))
	}
	now := time.Now()
	until := f.until
	if f.calls == 2 {
		until = now.Add(5 * time.Second)
	}
	return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, Scopes: []string{"evidence:read"}, VerifiedAt: now, ValidUntil: until}, nil
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	until time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(until time.Time) error { w.until = until; return nil }

func TestMCPRejectionPreservesOriginalDeadlineThroughFinalRead(t *testing.T) {
	for _, late := range []bool{false, true} {
		h, _, _, rows, _ := auditedMCPFixture(t)
		current := &finalRejectionIdentity{until: time.Now().Add(100 * time.Millisecond), late: late}
		req := httptest.NewRequest("POST", "https://example.invalid/mcp", nil)
		w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		delivery := &operationDeadline{until: time.Now().Add(5 * time.Second)}
		ok := h.rejectIngress(w, req, current, delivery, "unknown", []byte("{}"), presentation.IngressInvalid)
		if n := rows.count(); n != 1 {
			t.Fatal("missing audit", n)
		}
		if late {
			if ok || w.Code != 503 || !w.until.IsZero() {
				t.Fatal("fresh identity renewed old rejection", w.Code, w.until)
			}
		} else if !ok || w.until.IsZero() || w.until.After(current.until) {
			t.Fatal("response socket not bounded", w.Code, w.until, current.until)
		}
	}
}

func TestMCPReplyWriterRetainsMetadataClosureFence(t *testing.T) {
	for _, closed := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		until, _ := ctx.Deadline()
		delivery := &operationDeadline{until: until}
		if !delivery.retain(presentation.OperationReply{Body: []byte(`{"status":"ok"}`), ValidUntil: until}) {
			t.Fatal("metadata reply not retained")
		}
		if closed {
			delivery.close(ctx)
		}
		w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		sent, err := delivery.write(ctx, w, 200, []byte(`{"result":"metadata"}`), until)
		cancel()
		if closed {
			if err == nil || sent || w.Body.Len() != 0 {
				t.Fatal("closed metadata reply escaped")
			}
		} else if err != nil || !sent || w.Body.String() != `{"result":"metadata"}` || !w.until.Equal(until) || w.Header().Get("Content-Length") != "" {
			t.Fatal("unowned metadata changed", err)
		}
	}
}
