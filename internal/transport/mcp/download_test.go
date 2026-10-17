package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

type mcpDownloadFixture struct{ stops atomic.Int64 }

func (f *mcpDownloadFixture) PrepareContextDownload(context.Context, identities.CurrentIdentity, string, string) (evidence.ContextDownloadView, error) {
	return evidence.ContextDownloadView{}, artifact.ErrDownloadUnavailable
}
func (f *mcpDownloadFixture) GetContextDownload(context.Context, identities.CurrentIdentity, string) (evidence.ContextDownloadView, error) {
	return evidence.ContextDownloadView{}, artifact.ErrDownloadUnavailable
}
func (f *mcpDownloadFixture) CancelContextDownload(ctx context.Context, current identities.CurrentIdentity, id, key, request string) (artifact.DownloadStopReceipt, error) {
	i, e := current.ResolveIdentity(ctx)
	if e != nil {
		return artifact.DownloadStopReceipt{}, e
	}
	f.stops.Add(1)
	return artifact.DownloadStopReceipt{DownloadID: id, RequestID: request, State: "Cancelled", AuditState: "pending", ObservedAt: time.Now(), ValidUntil: i.ValidUntil}, nil
}
func TestMCPStopWithoutEvidenceScopesSurvivesNormalExecutionSaturation(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			var h *Handler
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
			defer server.Close()
			f := &mcpDownloadFixture{}
			ops, e := presentation.NewContextDownloadOperations(presentation.ContextDownloadOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000080" }}, f, f)
			if e != nil {
				t.Fatal(e)
			}
			h, e = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 1, MaxPerIdentity: 1}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
				i := testIdentity()
				i.Scopes = []string{"openid"}
				return i, nil
			}), ops)
			if e != nil {
				t.Fatal(e)
			}
			// Occupy the whole normal business lane and its principal allowance. Parsing
			// and the independently bounded Stop lane must still complete.
			h.normalWork <- struct{}{}
			defer func() { <-h.normalWork }()
			h.normalFlight[testIdentity().Principal] = 1
			discovery, _ := send(t, server, rpcRequest(t, server, version, "tools/list", nil))
			if discovery.StatusCode != 200 {
				t.Fatal("normal work blocked Stop discovery", discovery.StatusCode)
			}
			request := rpcRequest(t, server, version, "tools/call", map[string]any{"name": "cancel_artifact_download", "arguments": map[string]any{"download_id": "00000000-0000-4000-8000-000000000090", "idempotency_key": "same-key"}})
			response, body := send(t, server, request)
			if response.StatusCode != 200 || f.stops.Load() != 1 || !strings.Contains(string(body), "Cancelled") {
				t.Fatal(response.StatusCode, string(body), f.stops.Load())
			}
			for _, field := range []string{"artifact_id", "filename", "sha256"} {
				if strings.Contains(string(body), field) {
					t.Fatal("stop leaked native metadata", field)
				}
			}
		})
	}
}
func TestMCPInvalidStopArgumentsDoNotSpendStopExecutionSlot(t *testing.T) {
	var h *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	defer server.Close()
	f := &mcpDownloadFixture{}
	ops, e := presentation.NewContextDownloadOperations(presentation.ContextDownloadOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000080" }}, f, f)
	if e != nil {
		t.Fatal(e)
	}
	h, e = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 1, MaxPerIdentity: 1}, resolverFunc(func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil }), ops)
	if e != nil {
		t.Fatal(e)
	}
	h.normalWork <- struct{}{}
	defer func() { <-h.normalWork }()
	response, _ := send(t, server, rpcRequest(t, server, "2026-07-28", "tools/call", map[string]any{"name": "cancel_artifact_download", "arguments": map[string]any{"actor": "foreign"}}))
	if response.StatusCode != 429 || len(h.stopWork) != 0 || f.stops.Load() != 0 {
		t.Fatal("invalid stop entered reserved lane", response.StatusCode)
	}
}
