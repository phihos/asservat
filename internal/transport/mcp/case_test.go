package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpCaseID = "00000000-0000-4000-8000-000000000080"

// Only transport fixtures. Production ordinary rights/audit remain C-16 ports.
type mcpCaseFixture struct {
	calls atomic.Int64
	now   func() time.Time
	until time.Time
	after func()
}

func (f *mcpCaseFixture) GetContextCase(context.Context, identities.CurrentIdentity, string) (catalog.ContextCase, error) {
	f.calls.Add(1)
	now := time.Now()
	if f.now != nil {
		now = f.now()
	}
	until := f.until
	if until.IsZero() {
		until = now.Add(time.Second)
	}
	if f.after != nil {
		f.after()
	}
	return catalog.ContextCase{CaseID: mcpCaseID, ObservedAt: now, ValidUntil: until, Artifacts: []catalog.ContextCaseArtifact{{ArtifactID: "00000000-0000-4000-8000-000000000081", CaptureID: "00000000-0000-4000-8000-000000000082", Target: authorization.Target{ClusterID: mcpCaseID, NamespaceUID: "private-ns", WorkloadUID: "private-workload", PodUID: "private-pod"}, Version: artifact.Digest{1}, ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}}}, nil
}
func TestCaseMCPDiscoveryAndCallsUseOnlyConfiguredService(t *testing.T) {
	for _, withCaptures := range []bool{false, true} {
		var handler *Handler
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
		defer server.Close()
		f := &mcpCaseFixture{}
		var revoked atomic.Bool
		cases, e := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f)
		if e != nil {
			t.Fatal(e)
		}
		var captures *presentation.ContextOperations
		if withCaptures {
			stub := &mcpCaptureFixture{}
			captures, e = presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, stub, stub)
			if e != nil {
				t.Fatal(e)
			}
		}
		combined, e := presentation.NewInvestigationOperations(captures, cases)
		if e != nil {
			t.Fatal(e)
		}
		handler, e = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
			if revoked.Load() {
				return identity.Identity{}, identity.ErrDenied
			}
			return testIdentity(), nil
		}), combined)
		if e != nil {
			t.Fatal(e)
		}
		for _, version := range []string{"2025-11-25", "2026-07-28"} {
			response, b := send(t, server, rpcRequest(t, server, version, "tools/list", nil))
			var listed struct {
				Result sdk.ListToolsResult `json:"result"`
			}
			expected := 1
			if withCaptures {
				expected = 5
			}
			if response.StatusCode != 200 || json.Unmarshal(b, &listed) != nil || len(listed.Result.Tools) != expected {
				t.Fatalf("discovery: %d %s", response.StatusCode, b)
			}
			for _, unavailable := range []string{"prepare_artifact_download", "get_artifact_download", "cancel_artifact_download", "request_capture"} {
				if strings.Contains(string(b), `"name":"`+unavailable+`"`) {
					t.Fatal("unavailable service advertised", unavailable)
				}
			}
			call := func(arguments map[string]any) (*http.Response, []byte) {
				return send(t, server, rpcRequest(t, server, version, "tools/call", map[string]any{"name": "get_case", "arguments": arguments}))
			}
			before := f.calls.Load()
			response, b = call(map[string]any{"case_id": mcpCaseID, "include_raw": true})
			if f.calls.Load() != before || strings.Contains(string(b), `"kind":"pod-status"`) {
				t.Fatal("unsupported input reached metadata service")
			}
			response, b = call(map[string]any{"case_id": mcpCaseID})
			if response.StatusCode != 200 || !strings.Contains(string(b), `"structuredContent"`) || !strings.Contains(string(b), `"kind":"pod-status"`) || strings.Contains(string(b), "private-") {
				t.Fatalf("case call: %d %s", response.StatusCode, b)
			}
			// An actual SDK client validates the bounded output schema; JSON-RPC alone
			// would not reveal a schema or compatibility-text mismatch.
			client := sdk.NewClient(&sdk.Implementation{Name: "case-test", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
			hc := *server.Client()
			hc.Transport = bearerTransport{hc.Transport}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + Path, HTTPClient: &hc, MaxRetries: -1, DisableStandaloneSSE: true}, &sdk.ClientSessionOptions{ProtocolVersion: version})
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			got, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_case", Arguments: map[string]any{"case_id": mcpCaseID}})
			if err != nil || got.IsError || got.StructuredContent == nil || len(got.Content) != 1 {
				t.Fatalf("SDK case failed: %v %#v", err, got)
			}
			_ = session.Close()
			cancel()
		}
		f.after = func() { revoked.Store(true) }
		response, b := send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": "get_case", "arguments": map[string]any{"case_id": mcpCaseID}}))
		if response.StatusCode != 401 || strings.Contains(string(b), mcpCaseID) {
			t.Fatalf("revoked case exposed: %d %s", response.StatusCode, b)
		}
	}
}
func TestCaseMCPMetadataDeadlineSurvivesFinalIdentityCheck(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			base := time.Now()
			var elapsed atomic.Int64
			now := func() time.Time { return base.Add(time.Duration(elapsed.Load())) }
			f := &mcpCaseFixture{now: now, until: base.Add(100 * time.Millisecond)}
			var handler *Handler
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
			defer server.Close()
			cases, e := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: server.URL, Now: now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f)
			if e != nil {
				t.Fatal(e)
			}
			var checks atomic.Int64
			handler, e = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
				if checks.Add(1) == 4 {
					elapsed.Store(int64(200 * time.Millisecond))
				}
				i := testIdentity()
				i.VerifiedAt = now()
				i.ValidUntil = now().Add(20 * time.Second)
				return i, nil
			}), cases)
			if e != nil {
				t.Fatal(e)
			}
			handler.now = now
			response, b := send(t, server, rpcRequest(t, server, version, "tools/call", map[string]any{"name": "get_case", "arguments": map[string]any{"case_id": mcpCaseID}}))
			if checks.Load() != 4 || response.StatusCode != 503 || strings.Contains(string(b), mcpCaseID) || strings.Contains(string(b), "structuredContent") {
				t.Fatalf("expired case metadata survived: %d %s; checks%d", response.StatusCode, b, checks.Load())
			}
		})
	}
}
