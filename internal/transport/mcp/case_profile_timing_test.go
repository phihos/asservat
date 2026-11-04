package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type mcpProfileCaseFixture struct {
	mcpCaseFixture
	profile *artifact.ProfileAcquisitionMetadata
}

func (f *mcpProfileCaseFixture) GetContextCase(ctx context.Context, current identities.CurrentIdentity, id string) (catalog.ContextCase, error) {
	view, err := f.mcpCaseFixture.GetContextCase(ctx, current, id)
	a := &view.Artifacts[0]
	a.EvidenceType, a.DataClass, a.NativeType = "profile", "raw", artifact.PprofArtifact
	a.ProfileAcquisition = f.profile
	return view, err
}

// The real MCP SDK validates the published nested output schema and compatibility
// content, using synthetic authorized catalog metadata, not synthetic raw bytes.
func TestProfileAcquisitionCaseMCPHTTPAndSDKKeepUnknownLegacyWindow(t *testing.T) {
	var handler *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	f := &mcpProfileCaseFixture{profile: &artifact.ProfileAcquisitionMetadata{Type: "heap", Mode: "snapshot", ForceGC: true}}
	ops, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil }), ops)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		client := sdk.NewClient(&sdk.Implementation{Name: "profile-case-test", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
		hc := *server.Client()
		hc.Transport = bearerTransport{hc.Transport}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + Path, HTTPClient: &hc, MaxRetries: -1, DisableStandaloneSSE: true}, &sdk.ClientSessionOptions{ProtocolVersion: version})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_case", Arguments: map[string]any{"case_id": mcpCaseID}})
		session.Close()
		cancel()
		if err != nil || result.IsError || result.StructuredContent == nil || len(result.Content) != 1 {
			t.Fatal("MCP profile case failed", err, result)
		}
		body, err := json.Marshal(result.StructuredContent)
		if err != nil || wire.ValidateOutput("get_case", body) != nil || wire.ValidateBrowserOutput("get_case", body) != nil {
			t.Fatal("MCP/browser contract parity failed", err, string(body))
		}
		var out struct {
			Data struct {
				Artifacts []struct {
					Profile presentation.ProfileAcquisitionData `json:"profile_acquisition"`
				}
			}
		}
		if json.Unmarshal(body, &out) != nil || len(out.Data.Artifacts) != 1 {
			t.Fatal("profile case output")
		}
		got := out.Data.Artifacts[0].Profile
		if got.RequestedType != "heap" || got.Mode != "snapshot" || !got.ForceGC || got.RequestedDurationMillis != nil || got.StartedAt != nil || got.CompletedAt != nil || got.ClockUncertaintyMillis != nil || got.ProcessAttribution != "unknown" || got.WindowKind != "httpAcquisition" {
			t.Fatal("legacy profile metadata changed", got)
		}
	}
}
