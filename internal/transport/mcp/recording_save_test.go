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
	base, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, ordinary, mcpGroupedProgress{})
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
	names := map[string]bool{}
	var cursor string
	var response *http.Response
	var b []byte
	for page := 0; ; page++ {
		if page > len(composed.ToolNames()) {
			t.Fatal("tool discovery did not finish")
		}
		var params any
		if cursor != "" {
			params = map[string]any{"cursor": cursor}
		}
		response, b = send(t, server, rpcRequest(t, server, "2025-11-25", "tools/list", params))
		if response.StatusCode != 200 {
			t.Fatal(response.StatusCode, string(b))
		}
		var listed struct {
			Result struct {
				Tools      []struct{ Name string }
				NextCursor string `json:"nextCursor"`
			}
		}
		if json.Unmarshal(b, &listed) != nil || strings.Contains(string(b), `"target_handle"`) {
			t.Fatal("invalid discovery page", string(b))
		}
		for _, tool := range listed.Result.Tools {
			if names[tool.Name] {
				t.Fatal("duplicate discovery tool", tool.Name)
			}
			names[tool.Name] = true
		}
		if listed.Result.NextCursor == "" {
			break
		}
		cursor = listed.Result.NextCursor
	}
	if !names["list_recordings"] || !names["preview_recording_save"] || names["request_capture"] || names["cancel_capture"] {
		t.Fatal("wrong source tool set", names)
	}
	args := map[string]any{"target_ref": map[string]any{"cluster_id": "00000000-0000-4000-8000-000000000010", "namespace": "apps", "kind": "Deployment", "name": "api"}}
	response, b = send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": "list_recordings", "arguments": args}))
	if response.StatusCode != 200 || !strings.Contains(string(b), `"capture_enabled":false`) || !strings.Contains(string(b), `"recordings":[]`) || f.calls != 1 {
		t.Fatal(response.StatusCode, string(b), f.calls)
	}
	response, b = send(t, server, rpcRequest(t, server, "2025-11-25", "tools/call", map[string]any{"name": "get_capture", "arguments": map[string]any{"capture_id": "00000000-0000-4000-8000-000000000030"}}))
	if response.StatusCode != 200 || strings.Count(string(b), `"action_instance_id"`) < 2 || !strings.Contains(string(b), `"pod_name":"api-b"`) || !strings.Contains(string(b), `"phase":"Cancelled"`) {
		t.Fatal("grouped MCP progress lostchild", response.StatusCode, string(b))
	}

}

type mcpGroupedProgress struct{}

func (mcpGroupedProgress) Get(_ context.Context, _ identities.CurrentIdentity, id string) (value.ContextProgress, error) {
	return value.ContextProgress{CaptureID: id, Operation: "recordingSave", Revision: 3, Phase: "Partial", ValidUntil: time.Now().Add(time.Second), Actions: []value.ContextActionProgress{
		{InstanceID: "00000000-0000-4000-8000-000000000101", PodUID: "pod-a", PodName: "api-a", ActionID: "traffic", Phase: "Succeeded"},
		{InstanceID: "00000000-0000-4000-8000-000000000102", PodUID: "pod-b", PodName: "api-b", ActionID: "traffic", Phase: "Cancelled"},
	}}, nil
}
