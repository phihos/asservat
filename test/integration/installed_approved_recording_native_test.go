package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/transport/presentation"
)

type installedApprovedRecordingPreview struct {
	ResultAccessActions []presentation.RecorderResultAccessAction `json:"result_access_actions"`
	ID                  string                                    `json:"preview_id"`
	Expires             time.Time                                 `json:"expires_at"`
	Approval            bool                                      `json:"approval_required"`
	Enabled             bool                                      `json:"capture_enabled"`
	Digest              string                                    `json:"execution_digest"`
	Composition         json.RawMessage                           `json:"profile_composition"`
	Blockers            []struct {
		Code string `json:"code"`
	} `json:"blockers"`
	Pods      []struct{ UID, Name string } `json:"selected_pods"`
	Warnings  []string                     `json:"warnings"`
	Lifecycle struct {
		Actions []struct {
			ActionID string `json:"actionID"`
		} `json:"actions"`
	} `json:"lifecycle_plan"`
}

func (p installedApprovedRecordingPreview) readyForApproval(now time.Time) bool {
	return p.ID != "" && p.Approval && !p.Enabled && len(p.Pods) == 1 && p.Pods[0].UID != "" && now.Before(p.Expires) && len(p.Blockers) == 1 && p.Blockers[0].Code == "ApprovalRequired"
}

// Qualification submits the exact choice offered for the selected compiled
// action. Missing, duplicate, or changed choices must fail before approval.
func (p installedApprovedRecordingPreview) resultAccessOperations(actionID string, expected []string) ([]string, bool) {
	var operations []string
	for _, choice := range p.ResultAccessActions {
		if choice.ActionID != actionID {
			continue
		}
		if operations != nil || !slices.Equal(choice.Operations, expected) {
			return nil, false
		}
		operations = slices.Clone(choice.Operations)
	}
	return operations, len(operations) > 0
}

// Retry only the ordinary typed transient refusal, within the existing four
// read attempts. Successful plan-only previews are never retried or approved.
func installedApprovedRecordingCanRetry(reply installedJourneyEnvelope, code string) bool {
	var failure struct {
		Code      string `json:"code"`
		Retryable bool   `json:"retryable"`
	}
	return reply.Status == "error" && code == "NotAvailable" && json.Unmarshal(reply.Data, &failure) == nil && failure.Code == code && failure.Retryable
}

// The ordinary manual focuses qualify submission after preview expiry. The
// comparison focus reuses that capture path twice to qualify saved analysis.
func installedApprovedRecordingExpiryProof(focus string) bool {
	return focus != "profile-comparison" && !(focus == "manual-profile" && (installedHeapProfileVariant() || installedRuntimeTraceVariant() || installedTLSProfileTransport()))
}

// approvedRecordingArguments is the actual public request, validated offline
// before the expensive installed qualification. It is never authority.
func approvedRecordingArguments(cluster, namespace, workload string) map[string]any {
	if installedJourneyFocus() == "manual-arguments" {
		return manualArgumentsCaptureInput(cluster, namespace, workload, false)
	}
	if installedProfileFocus() {
		if installedRuntimeTraceVariant() {
			return manualRuntimeTraceArguments(cluster, namespace, workload)
		}
		if installedHeapProfileVariant() {
			return manualHeapProfileArguments(cluster, namespace, workload)
		}
		return manualProfileArguments(cluster, namespace, workload)
	}
	if installedJourneyFocus() == "manual-raw" {
		// ADR-279: one finite raw packet recording from a namespace profile.
		return manualRawArguments(cluster, namespace, workload)
	}
	if installedJourneyFocus() == "manual-http" {
		// ADR-282: one finite HTTP response-header recording from a namespace profile.
		return manualHTTPArguments(cluster, namespace, workload)
	}
	if installedJourneyFocus() == "manual-peers" {
		// ADR-283: one finite packet-header recording limited to a Kubernetes peer.
		return manualPeersArguments(cluster, namespace, workload)
	}
	if installedJourneyFocus() == "manual-mixed" {
		// ADR-276: packet and syscall finite recordings of one Pod at once.
		return map[string]any{
			"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
			"requested_retention_seconds": 600,
			"profile_composition": map[string]any{
				"components": []any{
					map[string]any{
						"id":         "network",
						"profileRef": map[string]string{"catalog": "builtin", "name": "network-connections", "version": "v1"},
						"overrides": []any{
							map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
							map[string]any{"actionID": "sample", "field": "packetAfter", "value": "10s"},
							map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "20s"},
						},
					},
					map[string]any{
						"id":         "calls",
						"profileRef": map[string]string{"catalog": "builtin", "name": "syscall-activity", "version": "v1"},
						"overrides": []any{
							map[string]any{"actionID": "syscalls", "field": "actionExecutionMode", "value": "onTrigger"},
							map[string]any{"actionID": "syscalls", "field": "syscallBefore", "value": "0s"},
							map[string]any{"actionID": "syscalls", "field": "syscallAfter", "value": "10s"},
							map[string]any{"actionID": "syscalls", "field": "actionTimeout", "value": "20s"},
						},
					},
				},
				"maxTotalBytes": 32 << 20,
				"maxDuration":   "20s",
			},
		}
	}
	if installedJourneyFocus() == "manual-syscall" {
		// B3: one finite manual syscall metadata recording of 5 seconds.
		return map[string]any{
			"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
			"requested_retention_seconds": 600,
			"profile_composition": map[string]any{
				"components": []any{map[string]any{
					"id":         "calls",
					"profileRef": map[string]string{"catalog": "builtin", "name": "syscall-activity", "version": "v1"},
					"overrides": []any{
						map[string]any{"actionID": "syscalls", "field": "actionExecutionMode", "value": "onTrigger"},
						map[string]any{"actionID": "syscalls", "field": "syscallBefore", "value": "0s"},
						map[string]any{"actionID": "syscalls", "field": "syscallAfter", "value": "5s"},
						map[string]any{"actionID": "syscalls", "field": "actionTimeout", "value": "15s"},
					},
				}},
				"maxTotalBytes": 16 << 20,
				"maxDuration":   "15s",
			},
		}
	}
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components": []any{map[string]any{
				"id":         "network",
				"profileRef": map[string]string{"catalog": "builtin", "name": "network-connections", "version": "v1"},
				"overrides": []any{
					map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
					map[string]any{"actionID": "sample", "field": "packetAfter", "value": "2s"},
					map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "10s"},
				},
			}},
			"maxTotalBytes": 16 << 20,
			"maxDuration":   "10s",
		},
	}
}

// Render only the node collector stage after the real regional installer
// has prepared its namespace and published the node endpoint.
func approvedRecordingCollectorRenderArgs(connectorNamespace, valuesPath string) []string {
	return []string{"template", "asservat", "../../charts/asservat", "--namespace", connectorNamespace, "--show-only", "templates/collector.yaml", "--kube-version", "1.37.0", "-f", valuesPath}
}

// stepUp exercises the same fresh-form route as the console, with the same
// human and cookie jar. The reference realm qualifies fresh password LoA1;
// it does not configure or claim MFA. The signed decision checks are the proof.
func (b *installedBrowser) approvedRecordingStepUp(t *testing.T, ctx context.Context, identity *installedIdentity, grantID string) {
	t.Helper()
	get := func(target string) (int, []byte, http.Header) {
		t.Helper()
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		response, err := b.client.Do(r)
		if err != nil {
			t.Fatal("step-up GET", err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(response.Body, 256<<10))
		return response.StatusCode, body, response.Header
	}
	expected := "/approvals/" + grantID
	status, _, headers := get(b.base + "/auth/step-up?return_to=" + url.QueryEscape(expected))
	auth, err := url.Parse(headers.Get("Location"))
	if status != http.StatusSeeOther || err != nil || !strings.HasPrefix(auth.String(), identity.Issuer+"/protocol/openid-connect/auth") || auth.Query().Get("max_age") != "0" || auth.Query().Get("acr_values") != "1" || auth.Query().Get("code_challenge_method") != "S256" || auth.Query().Get("state") == "" || auth.Query().Get("nonce") == "" {
		t.Fatal("step-up original PKCE request", status, err)
	}
	status, page, _ := get(auth.String())
	match := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	if status != http.StatusOK || len(match) != 2 {
		t.Fatal("existing SSO skipped fresh provider form", status)
	}
	action := html.UnescapeString(string(match[1]))
	if !strings.HasPrefix(action, identity.Issuer+"/login-actions/") {
		t.Fatal("step-up form escaped issuer")
	}
	form, _ := http.NewRequestWithContext(ctx, http.MethodPost, action, strings.NewReader(url.Values{"username": {"reviewer"}, "password": {identity.kc.UserPassword}}.Encode()))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := b.client.Do(form)
	if err != nil {
		t.Fatal("fresh provider sign-in", err)
	}
	io.Copy(io.Discard, io.LimitReader(response.Body, 256<<10))
	response.Body.Close()
	if response.StatusCode != http.StatusFound || !strings.HasPrefix(response.Header.Get("Location"), b.base+"/auth/callback?") {
		t.Fatal("fresh reviewer sign-in callback", response.StatusCode)
	}
	status, _, headers = get(response.Header.Get("Location"))
	if status != http.StatusSeeOther || headers.Get("Location") != expected {
		t.Fatal("step-up callback changed return", status)
	}
	status, body, _ := get(b.base + "/api/v1/session")
	var view struct {
		CSRF      string `json:"csrf_token"`
		Principal struct {
			Subject string `json:"subject_id"`
		} `json:"principal"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &view) != nil || len(view.CSRF) != 43 || view.Principal.Subject != identity.ReviewerSubject {
		t.Fatal("fresh reviewer session identity", status)
	}
	b.csrf = view.CSRF
}

// installedNativeDownload prepares, awaits and reads one native artifact whose
// filename extension is one of extensions.
func installedNativeDownload(t *testing.T, ctx context.Context, transport http.RoundTripper, identity *installedIdentity, origin, artifactID, key string, invoke func(string, any) (installedJourneyEnvelope, string), read func(string, any, any), diagnose func(), extensions ...string) ([]byte, string) {
	t.Helper()
	var download installedJourneyDownload
	// As in the main flow: preparation is an effect, so only the server's
	// continuation flag permits another exact same-key prepare.
	prepare := func() {
		t.Helper()
		reply, code := invoke("prepare_artifact_download", map[string]string{"artifact_id": artifactID, "idempotency_key": key})
		if code != "" || reply.Status != "ok" || json.Unmarshal(reply.Data, &download) != nil {
			diagnose()
			t.Fatal("mixed download preparation failed", code)
		}
	}
	prepare()
	for until := time.Now().Add(3 * time.Minute); download.State == "Preparing" && time.Now().Before(until); {
		if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
			t.Fatal(err)
		}
		if download.ContinuePreparation {
			prepare()
		} else {
			read("get_artifact_download", map[string]string{"download_id": download.DownloadID}, &download)
		}
	}
	if download.State != "Ready" || download.SizeBytes == nil {
		diagnose()
		t.Fatal("mixed download not ready", download.State)
	}
	response := installedJourneyContent(t, ctx, &http.Client{Transport: transport, Timeout: time.Minute}, strings.TrimSuffix(origin, "/")+download.ContentPath, identity.downloadToken(), nil)
	defer response.Body.Close()
	_, disposition, err := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	name := disposition["filename"]
	extension := filepath.Ext(name)
	native, readErr := io.ReadAll(io.LimitReader(response.Body, artifact.RecordingNativeLimit+1))
	digest := sha256.Sum256(native)
	if err != nil || readErr != nil || name != "artifact-"+artifactID+extension || !slices.Contains(extensions, extension) || response.StatusCode != http.StatusOK || int64(len(native)) != *download.SizeBytes || hex.EncodeToString(digest[:]) != download.SHA256 {
		t.Fatal("mixed native download does not match its metadata", name, err, readErr)
	}
	return native, extension
}
