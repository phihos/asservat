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

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

type previewUseCase struct{ calls atomic.Int64 }

func (p *previewUseCase) Preview(context.Context, identities.CurrentIdentity, []authapp.ProposedChange) (cfg.AccessPreview, time.Time, error) {
	p.calls.Add(1)
	return cfg.AccessPreview{}, time.Now().Add(time.Second), nil
}

// ADR-237: the browser-only administrator preview is composed into the shared
// operation set but MCP neither lists nor dispatches it.
func TestMCPOmitsBrowserOnlyAccessPreview(t *testing.T) {
	var handler *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	f := &mcpCaptureFixture{}
	captures, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f, f)
	if err != nil {
		t.Fatal(err)
	}
	base, err := presentation.NewInvestigationOperations(captures, nil)
	if err != nil {
		t.Fatal(err)
	}
	use := &previewUseCase{}
	preview, err := presentation.NewAccessPreviewOperations(server.URL, time.Now, func() string { return "00000000-0000-4000-8000-000000000098" }, use)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := presentation.NewInvestigationAccessPreviewOperations(base, preview)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ops.Tool("preview_access_change"); !ok {
		t.Fatal("preview not composed for the browser route")
	}
	handler, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
		return testIdentity(), nil
	}), ops)
	if err != nil {
		t.Fatal(err)
	}
	response, b := send(t, server, rpcRequest(t, server, "2026-07-28", "tools/list", nil))
	var listed struct {
		Result struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"result"`
	}
	if response.StatusCode != 200 || json.Unmarshal(b, &listed) != nil || len(listed.Result.Tools) == 0 {
		t.Fatalf("list: %d %s", response.StatusCode, b)
	}
	for _, tool := range listed.Result.Tools {
		if tool.Name == "preview_access_change" {
			t.Fatal("browser-only preview advertised over MCP")
		}
	}
	response, b = send(t, server, rpcRequest(t, server, "2026-07-28", "tools/call", map[string]any{"name": "preview_access_change", "arguments": map[string]any{"changes": []any{map[string]any{"action": "delete", "kind": "AccessBinding", "uid": "b"}}}}))
	if strings.Contains(string(b), `"structuredContent"`) || use.calls.Load() != 0 {
		t.Fatalf("browser-only preview dispatched over MCP: %d %s", response.StatusCode, b)
	}
}
