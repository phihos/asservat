package integration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
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
// regional workload, download it, then see access end when the operator
// revokes it and again when the capture expires. deny adds (true) or removes
// (false) the operator's Deny binding for the user's group. Every authority
// input is the installed product's own:
// the operator's AccessBinding, the permission stream, the regional capacity
// binding refreshed on demand (ADR-200) and the federation; nothing is seeded.
// diagnose prints the hub processes' logs before a failure ends the test.
// installedJourneyRetention is the requested evidence access lifetime in
// seconds: long enough to collect, publish and download, short enough to
// wait for expiry.
const installedJourneyRetention = 600

func installedJourney(t *testing.T, ctx context.Context, identity *installedIdentity, publicRoot []byte, address, origin string, diagnose func()) func(cluster, namespace, workload string, deny func(bool)) {
	return func(cluster, namespace, workload string, deny func(bool)) {
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
			"preset_ref": map[string]string{"name": "pod-status", "version": "v1"}, "requested_retention_seconds": installedJourneyRetention}, &preview)
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
		t.Logf("installed journey: MCP preview, request and resolution of a regional pod-status capture as the Keycloak user")
		// The regional executor collects; the publisher verifies and publishes
		// (ADR-203). Poll the capture until it is terminal, then its case until
		// the published artifact is listed, within bounded time.
		var progress struct {
			Phase  string `json:"phase"`
			CaseID string `json:"case_id"`
		}
		terminal := map[string]bool{"Succeeded": true, "Partial": true, "Failed": true, "Cancelled": true, "Indeterminate": true}
		deadline := time.Now().Add(5 * time.Minute)
		wait := func(what string, done func() bool) {
			t.Helper()
			for !done() {
				if time.Now().After(deadline) {
					diagnose()
					t.Fatal("installed journey: timed out waiting for", what)
				}
				time.Sleep(5 * time.Second)
			}
		}
		wait("a terminal capture", func() bool {
			call("get_capture", map[string]string{"capture_id": accepted.CaptureID}, &progress)
			return terminal[progress.Phase]
		})
		if progress.Phase != "Succeeded" || progress.CaseID == "" {
			diagnose()
			t.Fatal("installed capture was not collected", progress.Phase, progress.CaseID)
		}
		var investigation struct {
			Artifacts []struct {
				ArtifactID string `json:"artifact_id"`
			} `json:"artifacts"`
		}
		wait("the published artifact", func() bool {
			call("get_case", map[string]string{"case_id": progress.CaseID}, &investigation)
			return len(investigation.Artifacts) > 0
		})
		if len(investigation.Artifacts) != 1 {
			t.Fatal("installed case lists more than the one pod-status artifact", investigation.Artifacts)
		}
		t.Logf("installed journey: the regional capture was collected, verified and published")
		// A hub-local download worker (ADR-204) prepares the native file; the
		// same MCP client fetches it with its download-route token.
		var download struct {
			DownloadID  string `json:"download_id"`
			State       string `json:"state"`
			SizeBytes   *int64 `json:"size_bytes"`
			SHA256      string `json:"sha256"`
			ContentPath string `json:"content_path"`
		}
		call("prepare_artifact_download", map[string]string{"artifact_id": investigation.Artifacts[0].ArtifactID, "idempotency_key": "installed-journey-download"}, &download)
		wait("a prepared download", func() bool {
			if download.State == "Preparing" {
				call("get_artifact_download", map[string]string{"download_id": download.DownloadID}, &download)
			}
			return download.State != "Preparing"
		})
		if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil || download.SHA256 == "" {
			diagnose()
			t.Fatal("installed download was not prepared", download.State, download.ContentPath)
		}
		get, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(origin, "/")+download.ContentPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		get.Header.Set("Authorization", "Bearer "+identity.downloadToken())
		response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Minute}).Do(get)
		if err != nil {
			diagnose()
			t.Fatal("installed download content", err)
		}
		defer response.Body.Close()
		digest := sha256.New()
		size, err := io.Copy(digest, io.LimitReader(response.Body, *download.SizeBytes+1))
		if err != nil || response.StatusCode != http.StatusOK || size != *download.SizeBytes || hex.EncodeToString(digest.Sum(nil)) != download.SHA256 {
			diagnose()
			t.Fatal("installed download content differs from its prepared metadata", response.StatusCode, size, err)
		}
		t.Logf("installed journey: the Keycloak user downloaded the native pod-status file (%d bytes) through the hub-local worker", size)
		// Revocation: with the Deny binding the case is no longer available;
		// without it, it is again. Expiry: once the artifact's access ends,
		// the case no longer offers it and a new preparation is refused.
		available := func() (bool, time.Time) {
			t.Helper()
			result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_case", Arguments: map[string]string{"case_id": progress.CaseID}})
			if err != nil {
				t.Fatal("installed get_case", err)
			}
			raw, _ := json.Marshal(result.StructuredContent)
			var envelope struct {
				Status string `json:"status"`
				Data   struct {
					Artifacts []struct {
						ExpiresAt time.Time `json:"expires_at"`
					} `json:"artifacts"`
				} `json:"data"`
			}
			if json.Unmarshal(raw, &envelope) != nil || envelope.Status != "ok" && envelope.Status != "error" {
				t.Fatal("installed get_case reply", string(raw))
			}
			if envelope.Status != "ok" || len(envelope.Data.Artifacts) == 0 {
				return false, time.Time{}
			}
			return true, envelope.Data.Artifacts[0].ExpiresAt
		}
		until := func(what string, limit time.Duration, want bool) time.Time {
			t.Helper()
			end := time.Now().Add(limit)
			for {
				got, expires := available()
				if got == want {
					return expires
				}
				if time.Now().After(end) {
					diagnose()
					t.Fatal("installed journey: timed out waiting for", what)
				}
				time.Sleep(5 * time.Second)
			}
		}
		refused := func(key string) {
			t.Helper()
			result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "prepare_artifact_download", Arguments: map[string]string{"artifact_id": investigation.Artifacts[0].ArtifactID, "idempotency_key": key}})
			raw, _ := json.Marshal(result)
			var envelope struct {
				StructuredContent struct {
					Status string `json:"status"`
				} `json:"structuredContent"`
			}
			if err != nil || json.Unmarshal(raw, &envelope) != nil || envelope.StructuredContent.Status != "error" {
				t.Fatal("installed journey: a new download preparation was not refused", key, err, string(raw))
			}
		}
		deny(true)
		until("the revocation", 2*time.Minute, false)
		refused("installed-journey-revoked")
		t.Log("installed journey: after the operator's Deny binding the case and a new download preparation are refused")
		deny(false)
		expires := until("the restored access", 2*time.Minute, true)
		t.Logf("installed journey: removing the Deny binding restored access; access ends at %s", expires.Format(time.RFC3339))
		if wait := time.Until(expires); wait > 0 {
			if wait > installedJourneyRetention*time.Second {
				t.Fatal("installed artifact access outlasts the requested retention", expires)
			}
			time.Sleep(wait)
		}
		until("the expiry", 2*time.Minute, false)
		refused("installed-journey-expired")
		t.Log("installed journey: after expiry the case no longer offers the artifact and a new preparation is refused")
	}
}
