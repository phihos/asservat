package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestInstalledRecordingPassiveGetCapture503WithRealSDK(t *testing.T) {
	server := sdk.NewServer(&sdk.Implementation{Name: "synthetic-passive-progress", Version: "1"}, nil)
	type captureArgs struct {
		CaptureID string `json:"capture_id"`
	}
	sdk.AddTool(server, &sdk.Tool{Name: "get_capture"}, func(_ context.Context, _ *sdk.CallToolRequest, input captureArgs) (*sdk.CallToolResult, map[string]any, error) {
		return nil, map[string]any{"status": "ok", "data": map[string]string{"capture_id": input.CaptureID, "phase": "Failed"}}, nil
	})
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{JSONResponse: true})
	var mu sync.Mutex
	var captures []string
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var rpc struct {
				Method string `json:"method"`
				Params struct {
					Name      string      `json:"name"`
					Arguments captureArgs `json:"arguments"`
				} `json:"params"`
			}
			if json.Unmarshal(body, &rpc) == nil && rpc.Method == "tools/call" {
				mu.Lock()
				captures = append(captures, rpc.Params.Arguments.CaptureID)
				count := len(captures)
				mu.Unlock()
				if count == 1 {
					http.Error(w, "synthetic unavailable", http.StatusServiceUnavailable)
					return
				}
			}
		}
		handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	client := sdk.NewClient(&sdk.Implementation{Name: "passive-read-regression", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: httpServer.URL, HTTPClient: &http.Client{Transport: installedRecordingHTTPStatus{http.DefaultTransport}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	invoke := func(ctx context.Context, name string, args any) (installedJourneyEnvelope, string, error) {
		result, err := installedRecordingCallTool(ctx, session, name, args)
		if err != nil {
			return installedJourneyEnvelope{}, "", err
		}
		raw, _ := json.Marshal(result.StructuredContent)
		var reply installedJourneyEnvelope
		err = json.Unmarshal(raw, &reply)
		return reply, "", err
	}
	pauses := 0
	var progress captureArgs
	err = installedRecordingRead(ctx, "get_capture", captureArgs{CaptureID: "original-capture"}, &progress, invoke, func(_ context.Context, d time.Duration) error {
		if d != 2*time.Second {
			t.Fatal("read pause changed", d)
		}
		pauses++
		return nil
	}, t.Logf)
	if err != nil {
		t.Fatal("passive get_capture must spend its existing read budget on503", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(captures) != 2 || captures[0] != "original-capture" || captures[1] != captures[0] || progress.CaptureID != captures[0] || pauses != 1 {
		t.Fatal("passive recovery changed capture or HTTP attempt count", captures, progress, pauses)
	}
}
