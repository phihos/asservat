package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type installedJourneyBearer struct {
	inner http.RoundTripper
	token string
}

func (b installedJourneyBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.inner.RoundTrip(r)
}

// installedJourney returns the first installed S-02 slice: as the owned
// Keycloak user, over MCP through the public API's NodePort Service
// (ADR-202), preview, request and resolve a pod-status capture of the
// regional workload. Every authority input is the installed product's own:
// the operator's AccessBinding, the permission stream, the regional capacity
// binding refreshed on demand (ADR-200) and the federation; nothing is seeded.
// diagnose prints the hub processes' logs before a failure ends the test.
func installedJourney(t *testing.T, ctx context.Context, identity *installedIdentity, publicRoot []byte, address, origin string, diagnose func()) func(cluster, namespace, workload string) {
	return func(cluster, namespace, workload string) {
		t.Helper()
		if identity == nil {
			t.Log("installed journey skipped: the harness started no identity provider")
			return
		}
		cert, err := x509.ParseCertificate(publicRoot)
		if err != nil {
			t.Fatal("public listener root", err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		dial := &net.Dialer{Timeout: 5 * time.Second}
		transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dial.DialContext(ctx, network, address)
			}}
		defer transport.CloseIdleConnections()
		client := sdk.NewClient(&sdk.Implementation{Name: "installed-journey", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
		session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, identity.mcpToken()}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
		if err != nil {
			t.Fatal("installed MCP session", err)
		}
		defer session.Close()
		// A client retries a refused call: the first preview of a regional
		// workload records the refresh demand (ADR-200) and may outlast the
		// request's five-second bound; later attempts find the binding fresh.
		call := func(name string, arguments any, data any) {
			t.Helper()
			var failure string
			for attempt := 1; attempt <= 4; attempt++ {
				result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: arguments})
				if err != nil {
					failure = err.Error()
				} else {
					raw, _ := json.Marshal(result.StructuredContent)
					var envelope struct {
						Status string          `json:"status"`
						Data   json.RawMessage `json:"data"`
					}
					if json.Unmarshal(raw, &envelope) == nil && envelope.Status == "ok" && json.Unmarshal(envelope.Data, data) == nil {
						if attempt > 1 {
							t.Logf("installed %s succeeded on attempt %d", name, attempt)
						}
						return
					}
					failure = string(raw)
				}
				t.Logf("installed %s attempt %d: %s", name, attempt, failure)
				time.Sleep(2 * time.Second)
			}
			diagnose()
			t.Fatalf("installed %s: %s", name, failure)
		}
		var preview struct {
			PreviewID      string `json:"preview_id"`
			CaptureEnabled bool   `json:"capture_enabled"`
			SelectedPods   []struct {
				UID string `json:"uid"`
			} `json:"selected_pods"`
		}
		call("preview_capture", map[string]any{"target_ref": map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
			"preset_ref": map[string]string{"name": "pod-status", "version": "v1"}, "requested_retention_seconds": 3600}, &preview)
		if !preview.CaptureEnabled || len(preview.SelectedPods) != 1 || preview.PreviewID == "" {
			t.Fatal("installed preview did not pin the regional Pod", preview)
		}
		request := map[string]string{"preview_id": preview.PreviewID, "idempotency_key": "installed-journey-capture"}
		var accepted struct {
			CaptureID string `json:"capture_id"`
		}
		call("request_capture", request, &accepted)
		var resolved struct {
			State     string `json:"state"`
			CaptureID string `json:"capture_id"`
		}
		call("resolve_capture_request", request, &resolved)
		if accepted.CaptureID == "" || resolved.State != "accepted" || resolved.CaptureID != accepted.CaptureID {
			t.Fatal("installed request was not accepted once", accepted, resolved)
		}
		var progress map[string]any
		call("get_capture", map[string]string{"capture_id": accepted.CaptureID}, &progress)
		t.Logf("installed journey: MCP preview, request and resolution of a regional pod-status capture as the Keycloak user; progress %v", progress["state"])
	}
}
