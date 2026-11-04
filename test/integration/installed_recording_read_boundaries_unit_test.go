package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestInstalledRecordingPassiveReadBoundariesWithRealSDK(t *testing.T) {
	for _, tc := range []struct {
		name, tool       string
		statuses         []int
		attempts, pauses int
		wantOK           bool
	}{
		{"exhausted", "get_capture", []int{503}, 4, 3, false},
		{"unauthenticated", "get_capture", []int{401}, 1, 0, false},
		{"forbidden", "get_capture", []int{403}, 1, 0, false},
		{"bad-gateway", "get_capture", []int{502}, 1, 0, false},
		{"unknown-status", "get_capture", []int{500}, 1, 0, false},
		{"network", "get_capture", []int{-1}, 1, 0, false},
		{"unknown-sdk-error", "get_capture", []int{-2}, 1, 0, false},
		{"one-shared-budget", "get_capture", []int{-3, 503, -3, 503, 0}, 4, 3, false},
		{"typed-then503-success", "get_capture", []int{-3, 503, 0}, 3, 2, true},
		{"request-single", "request_capture", []int{503}, 1, 0, false},
		{"cancel-single", "cancel_capture", []int{503}, 1, 0, false},
		{"preview-single", "preview_capture", []int{503}, 1, 0, false},
		{"resolve-single", "resolve_capture_request", []int{503}, 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			invoke, calls := installedRecordingSDKBoundaryFixture(t, ctx, tc.tool, tc.statuses)
			originalDeadline, _ := ctx.Deadline()
			pauses, logs := 0, 0
			var progress struct {
				CaptureID string `json:"capture_id"`
			}
			err := installedRecordingRead(ctx, tc.tool, map[string]string{"capture_id": "original-capture"}, &progress, func(call context.Context, name string, args any) (installedJourneyEnvelope, string, error) {
				if deadline, ok := call.Deadline(); !ok || !deadline.Equal(originalDeadline) {
					t.Fatal("read renewed caller deadline")
				}
				return invoke(call, name, args)
			}, func(call context.Context, d time.Duration) error {
				if deadline, ok := call.Deadline(); d != 2*time.Second || !ok || !deadline.Equal(originalDeadline) {
					t.Fatal("pause changed original bound", d)
				}
				pauses++
				return nil
			}, func(format string, args ...any) { logs++; t.Logf(format, args...) })
			observed := calls()
			if (err == nil) != tc.wantOK || len(observed) != tc.attempts || pauses != tc.pauses {
				t.Fatal("read budget/status mismatch", err, observed, pauses)
			}
			for _, id := range observed {
				if id != "original-capture" {
					t.Fatal("capture identity changed", observed)
				}
			}
			if tc.wantOK && progress.CaptureID != "original-capture" {
				t.Fatal("success replaced original capture")
			}
			if tc.name == "exhausted" && logs != 4 {
				t.Fatal("each503 must be logged", logs)
			}
		})
	}
}

func TestInstalledRecordingPassiveReadCancellationWithRealSDK(t *testing.T) {
	for _, mode := range []string{"before-call", "during-pause", "deadline-during-pause"} {
		t.Run(mode, func(t *testing.T) {
			parent, stop := context.WithTimeout(context.Background(), 30*time.Second)
			defer stop()
			invoke, calls := installedRecordingSDKBoundaryFixture(t, parent, "get_capture", []int{503})
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			if mode == "before-call" {
				cancel()
			}
			if mode == "deadline-during-pause" {
				var end context.CancelFunc
				ctx, end = context.WithTimeout(parent, 100*time.Millisecond)
				defer end()
			}
			pauses := 0
			err := installedRecordingRead(ctx, "get_capture", map[string]string{"capture_id": "original-capture"}, &struct{}{}, invoke, func(call context.Context, d time.Duration) error {
				pauses++
				if mode == "during-pause" {
					cancel()
					return call.Err()
				}
				return installedJourneyPause(call, d)
			}, t.Logf)
			wantAttempts := 1
			if mode == "before-call" {
				wantAttempts = 0
			}
			if (!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)) || len(calls()) != wantAttempts || pauses != wantAttempts {
				t.Fatal("parent cancellation permitted another attempt", err, calls(), pauses)
			}
		})
	}
}

// Synthetic HTTP failures wrap the actual pinned SDK; no production authority
// or effect is supplied. Negative status codes are finite fixture conditions:
// -1 lost connection, -2 malformed protocol reply, -3 typed retryable denial.
func installedRecordingSDKBoundaryFixture(t *testing.T, ctx context.Context, tool string, statuses []int) (installedRecordingInvoke, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var captures []string
	statusAt := func(n int) int {
		if n >= len(statuses) {
			n = len(statuses) - 1
		}
		return statuses[n]
	}
	server := sdk.NewServer(&sdk.Implementation{Name: "synthetic-passive-boundaries", Version: "1"}, nil)
	sdk.AddTool(server, &sdk.Tool{Name: tool}, func(_ context.Context, _ *sdk.CallToolRequest, input map[string]string) (*sdk.CallToolResult, map[string]any, error) {
		mu.Lock()
		n := len(captures) - 1
		mu.Unlock()
		if statusAt(n) == -3 {
			return nil, map[string]any{"status": "error", "data": map[string]any{"code": "NotAvailable", "retryable": true}}, nil
		}
		return nil, map[string]any{"status": "ok", "data": map[string]string{"capture_id": input["capture_id"]}}, nil
	})
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{JSONResponse: true})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var rpc struct {
				Method string `json:"method"`
				Params struct {
					Arguments map[string]string `json:"arguments"`
				} `json:"params"`
			}
			if json.Unmarshal(body, &rpc) == nil && rpc.Method == "tools/call" {
				mu.Lock()
				captures = append(captures, rpc.Params.Arguments["capture_id"])
				n := len(captures) - 1
				mu.Unlock()
				switch status := statusAt(n); {
				case status > 0:
					http.Error(w, "synthetic failure", status)
					return
				case status == -1:
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				case status == -2:
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte("not JSON"))
					return
				}
			}
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(httpServer.Close)
	client := sdk.NewClient(&sdk.Implementation{Name: "passive-boundary-regression", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: httpServer.URL, HTTPClient: &http.Client{Transport: installedRecordingHTTPStatus{http.DefaultTransport}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return func(call context.Context, name string, args any) (installedJourneyEnvelope, string, error) {
		result, err := installedRecordingCallTool(call, session, name, args)
		if err != nil {
			return installedJourneyEnvelope{}, "", err
		}
		raw, _ := json.Marshal(result.StructuredContent)
		var reply installedJourneyEnvelope
		if err := json.Unmarshal(raw, &reply); err != nil {
			return reply, "", err
		}
		var failure struct {
			Code string `json:"code"`
		}
		if reply.Status == "error" {
			json.Unmarshal(reply.Data, &failure)
		}
		return reply, failure.Code, nil
	}, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), captures...) }
}
