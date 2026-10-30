package mcp

import (
	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/presentation"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type mcpRecordingFixture struct{ calls int }

func (f *mcpRecordingFixture) List(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, string, string, int) (app.RecordingPage, error) {
	f.calls++
	now := time.Now()
	return app.RecordingPage{ExpiresAt: now.Add(time.Minute), ValidUntil: now.Add(time.Second)}, nil
}
func (*mcpRecordingFixture) Preview(context.Context, identities.CurrentIdentity, app.RecordingSavePreviewRequest) (app.ContextPreviewResult, error) {
	return app.ContextPreviewResult{}, value.ErrUnavailable
}
func TestRecordingMCPRegistersPassiveToolsWithoutEnablingCollection(t *testing.T) {
	var handler *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	ordinary := &mcpCaptureFixture{}
	base, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, ordinary, ordinary)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := presentation.NewInvestigationOperations(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &mcpRecordingFixture{}
	saves, err := presentation.NewRecordingSaveOperations(presentation.RecordingSaveOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f)
	if err != nil {
		t.Fatal(err)
	}
	composed, err := presentation.NewInvestigationRecordingSaveOperations(aggregate, saves)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
		i := testIdentity()
		i.Scopes = append(i.Scopes, "evidence:capture")
		return i, nil
	}), composed)
	if err != nil {
		t.Fatal(err)
	}
	response, b := send(t, server, rpcRequest(t, server, "2025-11-25", "tools/list", nil))
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, string(b))
	}
	var listed struct {
		Result struct{ Tools []struct{ Name string } }
	}
	if json.Unmarshal(b, &listed) != nil {
		t.Fatal(string(b))
	}
	names := map[string]bool{}
	for _, tool := range listed.Result.Tools {
		names[tool.Name] = true
	}
	if !names["list_recordings"] || !names["preview_recording_save"] || names["request_capture"] || names["cancel_capture"] || strings.Contains(string(b), `"target_handle"`) {
		t.Fatal("wrong source tool set", string(b))
	}
	args := map[string]any{"target_ref": map[string]any{"cluster_id": "00000000-0000-4000-8000-000000000010", "namespace": "apps", "kind": "Deployment", "name": "api"}}
	response, b = send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": "list_recordings", "arguments": args}))
	if response.StatusCode != 200 || !strings.Contains(string(b), `"capture_enabled":false`) || !strings.Contains(string(b), `"recordings":[]`) || f.calls != 1 {
		t.Fatal(response.StatusCode, string(b), f.calls)
	}
}
