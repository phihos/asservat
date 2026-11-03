package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

type mcpRawRequest struct {
	presentation.GrantUseCase
	calls int
}

func (f *mcpRawRequest) RequestRaw(context.Context, identities.CurrentIdentity, authapp.RawQueryRequestInput) (authorization.Grant, bool, error) {
	f.calls++
	return authorization.Grant{}, false, authapp.ErrGrantUnavailable
}
func TestRawAccessMCPUsesSharedGrantOperation(t *testing.T) {
	var handler *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	calls := &mcpRawRequest{}
	operations, err := presentation.NewGrantOperations(server.URL, time.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, calls)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil }), operations)
	if err != nil {
		t.Fatal(err)
	}
	response, b := send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": "request_raw_access", "arguments": map[string]any{"case_id": "00000000-0000-4000-8000-000000000001", "artifact_digests": []string{strings.Repeat("1", 64)}, "operations": []string{"download_artifact"}, "reason": "inspect saved evidence", "max_bytes": 512, "expires_in_seconds": 3600, "idempotency_key": "same-key"}}))
	if response.StatusCode != 200 || calls.calls != 1 || !strings.Contains(string(b), `"code":"NotAvailable"`) {
		t.Fatal("MCP did not call shared raw request", response.StatusCode, calls.calls, string(b))
	}
}
