package mcp

import (
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
	"context"
	"encoding/json"
	"fmt"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type maximumReasonProgress struct{ *mcpCaptureFixture }

func (f maximumReasonProgress) Get(ctx context.Context, current identities.CurrentIdentity, id string) (value.ContextProgress, error) {
	p, err := f.mcpCaptureFixture.Get(ctx, current, id)
	p.Operation = "recordingSave"
	text := strings.Repeat("\x00", 512)
	p.Reason = &text
	p.ReasonState = "available"
	for i := 0; i < 16; i++ {
		p.Actions = append(p.Actions, value.ContextActionProgress{InstanceID: fmt.Sprintf("00000000-0000-4000-8000-%012d", 101+i), PodUID: strings.Repeat("u", 128), PodName: strings.Repeat("p", 253), ActionID: strings.Repeat("a", 63), Phase: "Finalizing", ReasonCode: strings.Repeat("R", 64)})
	}
	return p, err
}
func TestMaximumGroupedReasonUsesUnchangedSDKFrameBound(t *testing.T) {
	var handler *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	ordinary := &mcpCaptureFixture{}
	ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, ordinary, maximumReasonProgress{ordinary})
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
		i := testIdentity()
		i.Scopes = append(i.Scopes, "evidence:capture")
		return i, nil
	}), ops)
	if err != nil {
		t.Fatal(err)
	}
	observer := &recordingFrameObserver{next: bearerTransport{server.Client().Transport}}
	hc := *server.Client()
	hc.Transport = observer
	client := sdk.NewClient(&sdk.Implementation{Name: "reason-bound", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + Path, HTTPClient: &hc, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	called, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_capture", Arguments: map[string]any{"capture_id": "00000000-0000-4000-8000-000000000030"}})
	if err != nil || called.IsError || len(called.Content) != 1 || called.StructuredContent == nil {
		t.Fatal("actual SDK call", err, called)
	}
	text := called.Content[0].(*sdk.TextContent).Text
	var body struct {
		Data struct {
			Reason  string `json:"reason"`
			State   string `json:"reason_state"`
			Actions []any  `json:"actions"`
		}
	}
	if json.Unmarshal([]byte(text), &body) != nil || body.Data.Reason != strings.Repeat("\x00", 512) || body.Data.State != "available" || len(body.Data.Actions) != 16 {
		t.Fatal("lost parent metadata")
	}
	if len(text) > 24<<10 || observer.maximum.Load() > MaxResponseBytes {
		t.Fatal("unchanged bound exceeded", len(text), observer.maximum.Load())
	}
	t.Logf("actualSDK max16+512escaped reason raw=%d frame=%d", len(text), observer.maximum.Load())
}
