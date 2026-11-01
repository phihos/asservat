package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/presentation"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type mcpCaptureFixture struct {
	calls         atomic.Int64
	continuations atomic.Int64
	after         func()
	until         time.Time
}

func (f *mcpCaptureFixture) deadline() time.Time {
	if !f.until.IsZero() {
		return f.until
	}
	return time.Now().Add(5 * time.Second)
}
func (f *mcpCaptureFixture) CheckDiagnostic(context.Context, identities.CurrentIdentity, targets.WorkloadRequest) (time.Time, error) {
	return f.deadline(), nil
}
func (f *mcpCaptureFixture) Preview(context.Context, identities.CurrentIdentity, value.ContextIntent) (app.ContextPreviewResult, error) {
	return app.ContextPreviewResult{}, value.ErrUnavailable
}
func (f *mcpCaptureFixture) Request(_ context.Context, current identities.CurrentIdentity, preview, key string) (value.Accepted, error) {
	if _, err := current.ResolveIdentity(context.Background()); err != nil {
		return value.Accepted{}, err
	}
	if preview != "00000000-0000-4000-8000-000000000020" || key != "same-key" {
		return value.Accepted{}, value.ErrInvalid
	}
	f.calls.Add(1)
	if f.after != nil {
		f.after()
	}
	return value.Accepted{CaptureID: "00000000-0000-4000-8000-000000000030", MetadataValidUntil: f.deadline()}, nil
}
func (f *mcpCaptureFixture) Continue(ctx context.Context, current identities.CurrentIdentity, preview, key string) (value.Accepted, error) {
	if _, err := current.ResolveIdentity(ctx); err != nil {
		return value.Accepted{}, err
	}
	if preview != "00000000-0000-4000-8000-000000000020" || key != "same-key" {
		return value.Accepted{}, value.ErrInvalid
	}
	f.continuations.Add(1)
	return value.Accepted{CaptureID: "00000000-0000-4000-8000-000000000030", MetadataValidUntil: f.deadline()}, nil
}
func (f *mcpCaptureFixture) ResolveContextRequest(_ context.Context, current identities.CurrentIdentity, preview, key string) (value.ContextRequestDisposition, error) {
	if _, err := current.ResolveIdentity(context.Background()); err != nil {
		return value.ContextRequestDisposition{}, err
	}
	if preview != "00000000-0000-4000-8000-000000000020" || key != "same-key" {
		return value.ContextRequestDisposition{}, value.ErrInvalid
	}
	return value.ContextRequestDisposition{State: value.RequestClosed, ValidUntil: f.deadline()}, nil
}
func (f *mcpCaptureFixture) Get(context.Context, identities.CurrentIdentity, string) (value.ContextProgress, error) {
	return value.ContextProgress{CaptureID: "00000000-0000-4000-8000-000000000030", Revision: 1, Phase: "Pending", ActionPhase: "Pending", ReasonCode: "IntentAuditPending", ValidUntil: f.deadline()}, nil
}

func TestContextMCPRegistersQualifiedSchemasAndRetainsCurrentIdentity(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var handler *Handler
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
		defer server.Close()
		f := &mcpCaptureFixture{}
		var revoked atomic.Bool
		ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, CollectionEnabled: enabled, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f, f)
		if err != nil {
			t.Fatal(err)
		}
		handler, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
			if revoked.Load() {
				return identity.Identity{}, identity.ErrDenied
			}
			i := testIdentity()
			i.Scopes = append(i.Scopes, "evidence:capture")
			return i, nil
		}), ops)
		if err != nil {
			t.Fatal(err)
		}
		for _, version := range []string{"2025-11-25", "2026-07-28"} {
			client := sdk.NewClient(&sdk.Implementation{Name: "context-test-agent", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
			hc := *server.Client()
			hc.Transport = bearerTransport{hc.Transport}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			session, connectErr := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + Path, HTTPClient: &hc, MaxRetries: -1, DisableStandaloneSSE: true}, &sdk.ClientSessionOptions{ProtocolVersion: version})
			if connectErr != nil {
				cancel()
				t.Fatal(connectErr)
			}
			listedTools, listErr := session.ListTools(ctx, &sdk.ListToolsParams{})
			if listErr != nil || len(listedTools.Tools) < 3 {
				t.Fatalf("official discovery: %v", listErr)
			}
			called, callErr := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_capture", Arguments: map[string]any{"capture_id": "00000000-0000-4000-8000-000000000030"}})
			if callErr != nil || called.IsError || called.StructuredContent == nil || len(called.Content) != 1 {
				t.Fatalf("official tool call: %v %#v", callErr, called)
			}
			_ = session.Close()
			cancel()
			response, b := send(t, server, rpcRequest(t, server, version, "tools/list", nil))
			var listed struct {
				Result sdk.ListToolsResult `json:"result"`
			}
			if response.StatusCode != 200 || json.Unmarshal(b, &listed) != nil {
				t.Fatalf("list: %d %s", response.StatusCode, b)
			}
			expected := 4
			if enabled {
				expected = 5
			}
			if len(listed.Result.Tools) != expected {
				t.Fatalf("discovery count: %d %s", len(listed.Result.Tools), b)
			}
			if strings.Contains(string(b), `"$ref":"https:`) {
				t.Fatal("external schema dependency advertised")
			}
			response, b = send(t, server, rpcRequest(t, server, version, "tools/call", map[string]any{"name": "get_capture", "arguments": map[string]any{"capture_id": "00000000-0000-4000-8000-000000000030"}}))
			if response.StatusCode != 200 || !strings.Contains(string(b), `"structuredContent"`) || !strings.Contains(string(b), `"IntentAuditPending"`) {
				t.Fatalf("progress: %d %s", response.StatusCode, b)
			}
			response, b = send(t, server, rpcRequest(t, server, version, "tools/call", map[string]any{"name": "resolve_capture_request", "arguments": map[string]any{"preview_id": "00000000-0000-4000-8000-000000000020", "idempotency_key": "same-key"}}))
			if response.StatusCode != 200 || !strings.Contains(string(b), `"state":"closed"`) || strings.Contains(string(b), `"capture_id"`) {
				t.Fatalf("bounded recovery unavailable: %d %s", response.StatusCode, b)
			}
			if enabled {
				response, b = send(t, server, rpcRequest(t, server, version, "tools/call", map[string]any{"name": "request_capture", "arguments": map[string]any{"preview_id": "00000000-0000-4000-8000-000000000020", "idempotency_key": "same-key"}}))
				if response.StatusCode != 200 || !strings.Contains(string(b), `"phase":"Accepted"`) {
					t.Fatalf("request: %d %s", response.StatusCode, b)
				}
				requests, continuations := f.calls.Load(), f.continuations.Load()
				response, b = send(t, server, rpcRequest(t, server, version, "tools/call", map[string]any{"name": "request_capture", "arguments": map[string]any{"preview_id": "00000000-0000-4000-8000-000000000020", "idempotency_key": "same-key", "continue_acquisition": true}}))
				if response.StatusCode != 200 || !strings.Contains(string(b), `"phase":"Accepted"`) || f.calls.Load() != requests || f.continuations.Load() != continuations+1 {
					t.Fatal("explicit MCP continuation lost same-key branch", response.StatusCode, string(b))
				}
				response, b = send(t, server, rpcRequest(t, server, version, "tools/call", map[string]any{"name": "request_capture", "arguments": map[string]any{"preview_id": "00000000-0000-4000-8000-000000000020", "idempotency_key": "same-key", "continue_acquisition": false}}))
				if f.continuations.Load() != continuations+1 || f.calls.Load() != requests || strings.Contains(string(b), `"phase":"Accepted"`) {
					t.Fatal("false flag executed a request", response.StatusCode, string(b))
				}

			}
		}
		if enabled {
			f.after = func() { revoked.Store(true) }
			response, b := send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": "request_capture", "arguments": map[string]any{"preview_id": "00000000-0000-4000-8000-000000000020", "idempotency_key": "same-key"}}))
			if response.StatusCode != 401 || strings.Contains(string(b), "00000000-0000-4000-8000-000000000030") {
				t.Fatal("revoked token disclosed accepted receipt")
			}
		}
	}
}

func TestMCPRetainsOperationDeadlineThroughFinalIdentityCheck(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			base := time.Now()
			var elapsed atomic.Int64
			now := func() time.Time { return base.Add(time.Duration(elapsed.Load())) }
			f := &mcpCaptureFixture{until: base.Add(100 * time.Millisecond)}
			var h *Handler
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
			defer server.Close()
			ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, Now: now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f, f)
			if err != nil {
				t.Fatal(err)
			}
			var checks atomic.Int64
			h, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
				if checks.Add(1) == 4 {
					elapsed.Store(int64(200 * time.Millisecond))
				} // SDK encoded; final delivery identity blocks past shorter permission deadline.
				i := testIdentity()
				i.VerifiedAt = now()
				i.ValidUntil = now().Add(20 * time.Second)
				return i, nil
			}), ops)
			if err != nil {
				t.Fatal(err)
			}
			h.now = now
			var reasons []string
			h.Report = func(reason string) { reasons = append(reasons, reason) }
			response, b := send(t, server, rpcRequest(t, server, version, "tools/call", map[string]any{"name": "get_capture", "arguments": map[string]any{"capture_id": "00000000-0000-4000-8000-000000000030"}}))
			if checks.Load() != 4 {
				t.Fatal("test did not reach final identity check", checks.Load())
			}
			if response.StatusCode != 503 || response.Header.Get("WWW-Authenticate") != "" || strings.Contains(string(b), "00000000-0000-4000-8000-000000000030") || strings.Contains(string(b), "structuredContent") {
				t.Fatalf("expired operation authority disclosed metadata or invalidated identity: %d %s", response.StatusCode, b)
			}
			if len(reasons) != 1 || reasons[0] != "deadline-passed" {
				t.Fatalf("reported %q", reasons)
			}
		})
	}
}

type operationDeadlineWriter struct {
	http.ResponseWriter
	observed chan time.Time
}

func (w operationDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w operationDeadlineWriter) SetWriteDeadline(at time.Time) error {
	w.observed <- at
	return http.NewResponseController(w.ResponseWriter).SetWriteDeadline(at)
}
func TestMCPClampsActualSocketToOriginalOperationDeadline(t *testing.T) {
	until := time.Now().Add(2 * time.Second)
	f := &mcpCaptureFixture{until: until}
	observed := make(chan time.Time, 4)
	var h *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(operationDeadlineWriter{w, observed}, r) }))
	defer server.Close()
	ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f, f)
	if err != nil {
		t.Fatal(err)
	}
	h, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil }), ops)
	if err != nil {
		t.Fatal(err)
	}
	response, b := send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": "get_capture", "arguments": map[string]any{"capture_id": "00000000-0000-4000-8000-000000000030"}}))
	if response.StatusCode != 200 || !strings.Contains(string(b), "IntentAuditPending") {
		t.Fatalf("valid operation failed: %d %s", response.StatusCode, b)
	}
	if len(observed) != 2 {
		t.Fatal("missing final actual socket deadline", len(observed))
	}
	initial, final := <-observed, <-observed
	if !initial.After(until) || !final.Equal(until) {
		t.Fatal("operation deadline lost at socket", initial, final, until)
	}
	if strings.Contains(string(b), "ValidUntil") || strings.Contains(string(b), "MetadataValidUntil") {
		t.Fatal("private delivery lease serialized")
	}
}

func TestMCPFinalIdentityShorteningReachesSocket(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			var shorter time.Time
			f := &mcpCaptureFixture{}
			observed := make(chan time.Time, 4)
			var h *Handler
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(operationDeadlineWriter{w, observed}, r) }))
			defer server.Close()
			ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f, f)
			if err != nil {
				t.Fatal(err)
			}
			var checks atomic.Int64
			h, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
				i := testIdentity()
				if checks.Add(1) >= 4 {
					i.ValidUntil = shorter
				}
				return i, nil
			}), ops)
			if err != nil {
				t.Fatal(err)
			}
			// Fixture authority begins at dispatch, after schema/TLS construction.
			// Setup time is not part of this operation or its final identity interval.
			f.until = time.Now().Add(2 * time.Second)
			shorter = f.until.Add(-time.Second)
			response, b := send(t, server, rpcRequest(t, server, version, "tools/call", map[string]any{"name": "get_capture", "arguments": map[string]any{"capture_id": "00000000-0000-4000-8000-000000000030"}}))
			if response.StatusCode != 200 || !strings.Contains(string(b), "IntentAuditPending") || len(observed) != 2 || checks.Load() != 4 {
				t.Fatalf("unexpected path: %d %s checks=%d writes=%d", response.StatusCode, b, checks.Load(), len(observed))
			}
			<-observed
			if final := <-observed; !final.Equal(shorter) {
				t.Fatalf("final identity shortening lost: got=%v want=%v", final, shorter)
			}
		})
	}
}

type stoppedCall struct{ step string }

func (e stoppedCall) Error() string     { return "stopped" }
func (e stoppedCall) FixedStep() string { return e.step }

// failingOperations keeps the real tool catalog and fails every call without a
// delivery bound, as an audited call does when it stops.
type failingOperations struct {
	presentation.Operations
	err error
}

func (f failingOperations) Call(context.Context, identities.CurrentIdentity, string, json.RawMessage) (presentation.OperationReply, error) {
	return presentation.OperationReply{}, f.err
}

// A failed operation call answers 503 and reports the tool and where it
// stopped, not "final-identity-expired" (installed journey runs
// 39091358067/39091361821).
func TestMCPReportsAFailedOperationCall(t *testing.T) {
	f := &mcpCaptureFixture{}
	var h *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	defer server.Close()
	ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		err  error
		want string
	}{{stoppedCall{"audit-finish"}, "operation-failed preview_capture audit-finish"}, {errors.New("other"), "operation-failed preview_capture unavailable"}} {
		h, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
			i := testIdentity()
			i.VerifiedAt = time.Now()
			i.ValidUntil = time.Now().Add(20 * time.Second)
			return i, nil
		}), failingOperations{ops, c.err})
		if err != nil {
			t.Fatal(err)
		}
		var reasons []string
		h.Report = func(reason string) { reasons = append(reasons, reason) }
		response, _ := send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": "preview_capture", "arguments": map[string]any{
			"target_ref": map[string]string{"cluster_id": "00000000-0000-4000-8000-000000000001", "namespace": "payments", "kind": "Deployment", "name": "api"},
			"preset_ref": map[string]string{"name": "pod-status", "version": "v1"}, "requested_retention_seconds": 3600}}))
		if response.StatusCode != 503 || len(reasons) != 1 || reasons[0] != c.want {
			t.Fatalf("%d %q, want %q", response.StatusCode, reasons, c.want)
		}
	}
}
