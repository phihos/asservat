package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	analysis "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/presentation"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
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

// This focus uses the ordinary product installer and official chart. Its only
// privileged component runs on a guarded disposable runner, never a workstation.
func installApprovedRecordingCollector(t *testing.T, ctx context.Context, api kubernetes.Interface, config, image, installation, cluster, connectorNamespace string) {
	t.Helper()
	if _, err := os.Stat("/etc/asservat-disposable-host"); err != nil {
		t.Fatal("approved collector requires disposable host", err)
	}
	if image == "" {
		t.Fatal("approved collector lacks built image")
	}
	qualifyApprovedRecordingInputPermissions(t, ctx, api, config, connectorNamespace)
	source, err := api.CoreV1().ConfigMaps(connectorNamespace).Get(ctx, kube.RegionalNodes, meta.GetOptions{})
	if err != nil {
		t.Fatal("installed collector endpoint", err)
	}
	collector := map[string]any{"enabled": true, "image": image, "installationID": installation, "clusterID": cluster, "connector": source.Data}
	if installedAnyFocus("ongoing-save-disk") {
		// ADR-278: the administrator's opt-in encrypted-disk ring volume.
		collector["ringDisk"] = map[string]any{"enabled": true, "bytes": ongoingSaveDiskBytes}
	}
	if installedAnyFocus("live-observation") || installedAnyFocus("ongoing-incident") {
		// The administrator's node-side live processing opt-in; hub
		// delivery.liveRead separately authorizes viewers. The incident fixture
		// leaves one node slot so a second hub-eligible view must be shed.
		subscriptions := 4
		if installedAnyFocus("ongoing-incident") {
			subscriptions = 1
		}
		collector["live"] = map[string]any{"subscriptions": subscriptions, "memoryBytes": 4 << 20, "eventsPerSecond": 2000, "bytesPerSecond": 1 << 20, "processingNanosPerSecond": 50_000_000}
	}
	values := map[string]any{"mode": "cluster", "collector": collector}
	raw, _ := json.Marshal(values)
	path := filepath.Join(t.TempDir(), "collector-values.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// Hang bounds only: a local render, an apply and a 90 s rollout wait.
	render, rendered := installedBoundedCommand(ctx, 2*time.Minute, "helm", approvedRecordingCollectorRenderArgs(connectorNamespace, path)...)
	manifest, err := render.Output()
	rendered()
	if err != nil {
		t.Fatal("official collector chart", err)
	}
	apply, applied := installedBoundedCommand(ctx, 2*time.Minute, "kubectl", "--kubeconfig", config, "apply", "-f", "-")
	defer applied()
	apply.Stdin = bytes.NewReader(manifest)
	if out, err := apply.CombinedOutput(); err != nil {
		t.Fatalf("collector apply: %v %s", err, out)
	}
	roll, rolled := installedBoundedCommand(ctx, 3*time.Minute, "kubectl", "--kubeconfig", config, "-n", "asservat-collector", "rollout", "status", "daemonset/asservat-node", "--timeout=90s")
	defer rolled()
	if out, err := roll.CombinedOutput(); err != nil {
		t.Fatalf("collector readiness: %v %s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, end := installedBoundedCommand(context.Background(), 10*time.Second, "kubectl", "--kubeconfig", config, "-n", "asservat-collector", "logs", "-l", "app.kubernetes.io/name=asservat-node", "--tail=100", "--prefix")
			defer end()
			out, _ := logs.CombinedOutput()
			t.Logf("collector diagnostics: %s", out)
		}
	})
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

func qualifyInstalledApprovedRecording(t *testing.T, ctx context.Context, identity *installedIdentity, publicRoot []byte, address, origin, cluster, namespace, workload, regionalConfig string, diagnose func(), measurement *nativePacingMeasurement, historyPhase func(string), initialStorageFailure func(string), summaryCheck installedProjectionCheck, packetQueryCheck installedProjectionCheck, packetQueryDrain func(), argumentSource installedArgumentsSourceReader, stoppedDownload installedStoppedDownloadCheck, profileCapture ...installedProfileCaptureContinuation) {
	t.Helper()
	// Initial MCP transport/read failures can diagnose and terminate inside
	// helpers before recovery returns. Sample this one preview first, once.
	initialStoragePreview := ""
	fullDiagnose := diagnose
	diagnose = func() {
		if initialStoragePreview != "" {
			initialStorageFailure(initialStoragePreview)
			initialStoragePreview = ""
		}
		fullDiagnose()
	}
	if _, err := os.Stat("/etc/asservat-disposable-host"); err != nil {
		t.Fatal("approved recording requires disposable runner", err)
	}
	var finishSetup func() error
	if measurement != nil {
		var err error
		finishSetup, err = measurement.begin(ctx, "setup")
		if err != nil {
			t.Fatal("native workflow initial snapshot", err)
		}
		defer func() {
			if err := measurement.writeReport(); err != nil {
				t.Error("write native measurement report", err)
			}
		}()
	}
	cert, err := x509.ParseCertificate(publicRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(profileCapture) > 1 || installedJourneyFocus() == "profile-comparison" && (len(profileCapture) != 1 || profileCapture[0].Captured == nil) {
		t.Fatal("comparison capture requires its exact final native-source callback")
	}
	if len(profileCapture) == 0 || profileCapture[0].InitializeProcessing {
		identity.initializeProcessing(t, ctx, cert, address, origin, diagnose)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	dial := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DialContext: func(c context.Context, network, _ string) (net.Conn, error) {
		return dial.DialContext(c, network, address)
	}}
	defer transport.CloseIdleConnections()
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	tokens := identity.mcpTokenSource(origin)
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-approved-recording", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedRecordingHTTPStatus{installedJourneyBearer{transport, tokens.Token}}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	callOnce := func(call context.Context, name string, args any) (installedJourneyEnvelope, string, error) {
		result, err := installedRecordingCallTool(call, session, name, args)
		if err != nil {
			return installedJourneyEnvelope{}, "", err
		}
		return installedJourneyReplyCode(wire, name, result)
	}
	invoke := func(name string, args any) (installedJourneyEnvelope, string) {
		t.Helper()
		reply, code, err := callOnce(ctx, name, args)
		if err != nil {
			diagnose()
			t.Fatal("approved recording MCP", name, err)
		}
		return reply, code
	}
	readContext := func(call context.Context, name string, args, out any) {
		t.Helper()
		if err := installedRecordingRead(call, name, args, out, callOnce, installedJourneyPause, t.Logf); err != nil {
			diagnose()
			t.Fatal("approved recording read", name, err)
		}
	}
	read := func(name string, args, out any) { readContext(ctx, name, args, out) }
	var preview installedApprovedRecordingPreview
	arguments := approvedRecordingArguments(cluster, namespace, workload)
	if measurement != nil {
		arguments = nativePacingArguments(cluster, namespace, workload)
	}
	if installedJourneyFocus() == "manual-arguments" {
		definition, err := manualArgumentsProfileDefinition()
		if err != nil {
			t.Fatal(err)
		}
		publishNamespaceCaptureProfile(t, ctx, regionalConfig, namespace, manualArgumentsProfile, "v1", definition)
	}
	if installedJourneyFocus() == "manual-raw" {
		publishManualRawProfile(t, ctx, regionalConfig, namespace)
	}
	if installedJourneyFocus() == "manual-http" {
		// ADR-282: extract downloads use ordinary eligibility; no result_access.
		publishManualHTTPProfile(t, ctx, regionalConfig, namespace)
	}
	if installedProfileFocus() && installedHeapProfileVariant() {
		definition, err := manualHeapProfileDefinition()
		if err != nil {
			t.Fatal(err)
		}
		publishNamespaceCaptureProfile(t, ctx, regionalConfig, namespace, manualHeapProfileName, "v1", definition)
	}
	if installedProfileFocus() && installedRuntimeTraceVariant() {
		definition, err := manualRuntimeTraceDefinition()
		if err != nil {
			t.Fatal(err)
		}
		publishNamespaceCaptureProfile(t, ctx, regionalConfig, namespace, manualRuntimeTraceName, "v1", definition)
	}
	var peerIPs []string
	if installedJourneyFocus() == "manual-peers" {
		// ADR-283: the peer Pod runs before preview resolves its membership.
		cfg, err := clientcmd.BuildConfigFromFlags("", regionalConfig)
		if err != nil {
			t.Fatal(err)
		}
		region, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		peerIPs = createManualPeersClient(t, ctx, region, namespace, workload)
	}
	read("preview_capture", arguments, &preview)
	if installedJourneyFocus() == "manual-peers" {
		endpoints, digest, ok := manualPeersEndpoints(preview.Warnings)
		t.Logf("peer preview: %d Kubernetes endpoints resolved (members digest %s); blockers %v", endpoints, digest, preview.Blockers)
		if !ok || endpoints != len(peerIPs) {
			t.Fatal("peer preview did not resolve exactly the client Pod's addresses", endpoints, peerIPs, preview.Warnings)
		}
	}
	if !preview.readyForApproval(time.Now()) {
		t.Fatal("approved recording preview lacks its original window or has a non-approval blocker", preview.Blockers)
	}
	original := map[string]any{"preview_id": preview.ID, "idempotency_key": "approved-preview-" + preview.ID}
	if installedJourneyFocus() == "manual-raw" || installedProfileFocus() || installedJourneyFocus() == "manual-arguments" {
		// ADR-279: raw output downloads only through result-access children of
		// the requesting human's explicitly selected result client.
		if len(preview.Lifecycle.Actions) != 1 {
			t.Fatal("raw preview lacks its one action", preview.Lifecycle)
		}
		original["result_access"] = map[string]any{"actionIds": []string{preview.Lifecycle.Actions[0].ActionID}, "operations": []string{"download_artifact"}, "clientIDs": []string{installedProfileResultClient()},
			"maxArtifacts": 1, "maxBytes": 64 << 20, "maxOperations": 100, "notAfter": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	}
	if installedJourneyFocus() == "manual-raw" {
		access := original["result_access"].(map[string]any)
		access["operations"] = []string{"download_artifact", "pcap_query"}
		access["clientIDs"] = []string{"console", "mcp"}
	}
	if installedJourneyFocus() == "manual-arguments" {
		operations, ok := preview.resultAccessOperations(preview.Lifecycle.Actions[0].ActionID, []string{"download_artifact", "syscall_query"})
		if !ok {
			t.Fatal("actual arguments preview did not offer download and syscall query for its selected action")
		}
		access := original["result_access"].(map[string]any)
		access["operations"] = operations
		access["clientIDs"] = []string{"console", "mcp"}
	}
	pending, code := invoke("request_capture", original)
	var refused struct {
		URI string `json:"navigation_uri"`
	}
	if code != "ApprovalRequired" || json.Unmarshal(pending.Data, &refused) != nil {
		diagnose()
		t.Fatal("initial request did not open real review", code)
	}
	reviewURL, err := url.Parse(refused.URI)
	if err != nil {
		t.Fatal(err)
	}
	grantID := strings.TrimPrefix(reviewURL.Path, "/approvals/")
	if grantID == reviewURL.Path || len(grantID) != 36 {
		t.Fatal("pending review navigation")
	}
	// Another OAuth client of the requester cannot inherit its MCP grant.
	self := identity.consoleSession(t, ctx, cert, address, origin)
	browserCallCurrent := func(callCtx context.Context, b *installedBrowser, name string, input, out any) string {
		t.Helper()
		key := ""
		if fields, ok := input.(map[string]any); ok {
			key, _ = fields["idempotency_key"].(string)
		}
		reply, status, err := b.operation(callCtx, name, input, key)
		if err != nil || status != http.StatusOK {
			diagnose()
			t.Fatal("approval public browser operation", name, status, err)
		}
		var errorData struct {
			Code string `json:"code"`
		}
		if reply.Status != "ok" {
			json.Unmarshal(reply.Data, &errorData)
			return errorData.Code
		}
		if out != nil && json.Unmarshal(reply.Data, out) != nil {
			t.Fatal("approval browser data", name)
		}
		return ""
	}
	browserCall := func(b *installedBrowser, name string, input, out any) string {
		return browserCallCurrent(ctx, b, name, input, out)
	}
	var own struct {
		CanResume                    bool `json:"can_resume"`
		CanResolve                   bool `json:"can_resolve"`
		ResumeRequiresOriginalClient bool `json:"resume_requires_original_client"`
	}
	if code := browserCall(self, "get_grant", map[string]string{"grant_id": grantID}, &own); code != "" || own.CanResume || own.CanResolve || own.ResumeRequiresOriginalClient {
		t.Fatal("MCP grant transferred to browser client", code)
	}
	if code := browserCall(self, "request_capture", original, nil); code != "NotAvailable" && code != "ReviewChanged" {
		t.Fatal("public predictable key transferred MCP intent to browser", code)
	}
	if code := browserCall(self, "decide_review", map[string]any{"grant_id": grantID, "decision": "approve", "reason": "self approval must fail", "idempotency_key": "installed-self-refusal-" + grantID}, nil); code != "SelfApprovalRefused" {
		t.Fatal("self approval not refused", code)
	}
	kc := *identity.kc
	kc.username = "reviewer"
	reviewer := &installedIdentity{kc: &kc, Issuer: identity.Issuer, RootPEM: identity.RootPEM, ReviewerSubject: identity.ReviewerSubject}
	if reviewer.ReviewerSubject == "" {
		t.Fatal("independent reviewer absent")
	}
	browser := reviewer.consoleSession(t, ctx, cert, address, origin)
	browser.approvedRecordingStepUp(t, ctx, reviewer, grantID)
	if code := browserCall(browser, "decide_review", map[string]any{"grant_id": grantID, "decision": "approve", "reason": "independent installed metadata packet review", "idempotency_key": "installed-independent-approval-" + grantID}, nil); code != "" {
		diagnose()
		t.Fatal("signed independent decision", code)
	}
	var grant struct {
		Phase       string `json:"phase"`
		Digest      string `json:"execution_digest"`
		DataClass   string `json:"data_class"`
		Observation *struct {
			MaxSessionSeconds int64 `json:"max_session_seconds"`
			MaxObservedBytes  int64 `json:"max_observed_bytes"`
			MaxObservedEvents int64 `json:"max_observed_events"`
		} `json:"observation_limits"`
		Decision struct {
			By struct {
				Subject string `json:"subject"`
			} `json:"decided_by"`
		} `json:"decision"`
	}
	read("get_grant", map[string]string{"grant_id": grantID}, &grant)
	if grant.Phase != "Approved" || grant.Digest != preview.Digest || grant.Decision.By.Subject != reviewer.ReviewerSubject {
		t.Fatal("independent decision or exact plan changed", grant)
	}
	if installedProfileFocus() && grant.DataClass != "raw" {
		t.Fatal("live profile approval did not retain raw classification", grant.DataClass)
	}
	if installedJourneyFocus() == "manual-arguments" {
		if grant.DataClass != "raw" || grant.Observation == nil || grant.Observation.MaxObservedEvents != manualArgumentsRate*6 || grant.Observation.MaxObservedBytes != planvalue.SensitiveMaxObservedBytes {
			t.Fatal("argument review lost raw event/byte ceilings", grant)
		}
		t.Logf("raw argument review: %d observed probes, %d maximum observed bytes, %d maximum session seconds", grant.Observation.MaxObservedEvents, grant.Observation.MaxObservedBytes, grant.Observation.MaxSessionSeconds)
	}
	if installedJourneyFocus() == "manual-raw" {
		// ADR-279: payload approval names the raw class and observation limits.
		if grant.DataClass != "raw" || grant.Observation == nil || grant.Observation.MaxObservedBytes < 1 || grant.Observation.MaxSessionSeconds < 1 {
			t.Fatal("raw recording approval lacks raw class or observation limits", grant.DataClass, grant.Observation)
		}
		t.Logf("raw approval: observation limits %d bytes over %d seconds", grant.Observation.MaxObservedBytes, grant.Observation.MaxSessionSeconds)
	}
	if installedJourneyFocus() == "manual-http" {
		// ADR-282: header approval names the extract class and observation limits.
		if grant.DataClass != "extract" || grant.Observation == nil || grant.Observation.MaxObservedBytes < 1 || grant.Observation.MaxSessionSeconds < 1 {
			t.Fatal("HTTP header recording approval lacks extract class or observation limits", grant.DataClass, grant.Observation)
		}
		t.Logf("HTTP header approval: observation limits %d bytes over %d seconds", grant.Observation.MaxObservedBytes, grant.Observation.MaxSessionSeconds)
	}
	if code := browserCall(self, "get_grant", map[string]string{"grant_id": grantID}, &own); code != "" || own.CanResume || own.CanResolve || !own.ResumeRequiresOriginalClient {
		t.Fatal("approved original human lacks precise original-client guidance", code)
	}
	if code := browserCall(browser, "request_capture", original, nil); code != "NotAvailable" && code != "ReviewChanged" {
		t.Fatal("public predictable key transferred requester intent to reviewer", code)
	}
	var realWait time.Duration
	if installedApprovedRecordingExpiryProof(installedJourneyFocus()) {
		waitStarted := time.Now()
		if err := installedJourneyPause(ctx, time.Until(preview.Expires.Add(20*time.Millisecond))); err != nil {
			t.Fatal(err)
		}
		if !time.Now().After(preview.Expires) {
			t.Fatal("real preview has not expired")
		}
		realWait = time.Since(waitStarted)
	}
	// Ordinary approved HTTP traffic uses the exact selected Pod proxy.
	// The paced branch below uses its owned node directly to that same Pod.
	cfg, err := clientcmd.BuildConfigFromFlags("", regionalConfig)
	if err != nil {
		t.Fatal(err)
	}
	region, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	traffic, endTraffic := context.WithCancel(ctx)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		if measurement != nil || installedProfileFocus() {
			return
		}
		for traffic.Err() == nil {
			call, end := context.WithTimeout(traffic, 2*time.Second)
			request := region.CoreV1().RESTClient().Get().Namespace(namespace).Resource("pods").Name(preview.Pods[0].Name + ":8080").SubResource("proxy").Suffix("log")
			if installedJourneyFocus() == "manual-http" {
				request = manualHTTPTraffic(request)
			} else {
				request = request.Param("line", "synthetic-approved-recording")
			}
			_, _ = request.DoRaw(call)
			end()
			if installedJourneyPause(traffic, 100*time.Millisecond) != nil {
				return
			}
		}
	}()
	defer func() { endTraffic(); <-joined }()
	peerRuns := make(chan int, 1)
	if installedJourneyFocus() == "manual-peers" {
		// ADR-283: the peer's traffic to the exact selected Pod, beside the
		// API proxy traffic above that the peer filter must exclude.
		pod, err := region.CoreV1().Pods(namespace).Get(ctx, preview.Pods[0].Name, meta.GetOptions{})
		if err != nil || string(pod.UID) != preview.Pods[0].UID || pod.Status.PodIP == "" {
			t.Fatal("exact peer traffic target is unavailable", err)
		}
		go func() { peerRuns <- manualPeersTraffic(traffic, regionalConfig, namespace, pod.Status.PodIP) }()
		defer func() {
			endTraffic()
			// A run is bounded at one minute plus the command wait delay.
			if runs, ok := installedAwait(t, "peer traffic client", peerRuns, 90*time.Second); ok {
				t.Logf("peer client completed %d bounded traffic runs", runs)
			}
		}()
	}
	submitted := time.Now()
	var receipt struct {
		CaptureID string `json:"capture_id"`
	}
	requestCapture := func(input map[string]any) string {
		t.Helper()
		call, end := context.WithTimeout(ctx, 45*time.Second)
		defer end()
		result, err := session.CallTool(call, &sdk.CallToolParams{Name: "request_capture", Arguments: input})
		if err != nil {
			return "OutcomeUnknown"
		}
		reply, code, err := installedJourneyReplyCode(wire, "request_capture", result)
		if err != nil {
			t.Fatal("approved request contract", err)
		}
		if code == "" && json.Unmarshal(reply.Data, &receipt) != nil {
			t.Fatal("approved request receipt")
		}
		return code
	}
	trafficAttempted := measurement == nil
	var finishRecording func() error
	observeTraffic := func(current installedJourneyCaptureProgress, expectedID string) {
		if !trafficAttempted && current.CaptureID == expectedID && current.Phase == "Running" {
			measurement.ExecutionObservedAt = time.Now().UTC()
			if err := finishSetup(); err != nil {
				t.Fatal("native workflow setup snapshot", err)
			}
			finishRecording, err = measurement.begin(ctx, "recording")
			if err != nil {
				t.Fatal(err)
			}
			// Keep traffic off the serialized API Pod proxy while targeting the
			// same selected Pod UID/IP from its exact owned node network.
			pod, e := region.CoreV1().Pods(namespace).Get(ctx, preview.Pods[0].Name, meta.GetOptions{})
			if e != nil || string(pod.UID) != preview.Pods[0].UID || pod.Spec.NodeName == "" {
				t.Fatal("exact traffic Pod is unavailable", e)
			}
			if e := nativePacingRequireTargetProfile(pod); e != nil {
				t.Fatal("declared native-paced target", e)
			}
			// These two optional diagnostics consume existing time, never extend the
			// capture or gate authority. Each edge uses a short diagnostic context;
			// missing data is recorded as unavailable rather than a new failure gate.
			observeCPU := func() *nativeTrafficCPU {
				call, end := context.WithTimeout(ctx, 250*time.Millisecond)
				defer end()
				sample, e := nativeTrafficTargetCPU(call, region, pod)
				if e != nil {
					return nil
				}
				return &sample
			}
			beforeCPU := observeCPU()
			measurement.TrafficStartedAt = time.Now().UTC()
			measurement.Traffic, err = nativePacingNodeTraffic(ctx, measurement.traffic, pod.Spec.NodeName, pod.Status.PodIP)
			measurement.TrafficFinishedAt = time.Now().UTC()
			measurement.TargetCPU = nativePacingTargetCPUSamples(beforeCPU, observeCPU())
			// Consume this ONE attempt even when it reaches its own fixed deadline.
			// The helper's non-nil refusal/counts remain; near-full PCAP and all native
			// transfer/owner/ACK gates below still decide the actual qualification.
			trafficAttempted = true
			if err != nil {
				if !errors.Is(err, errNativeTrafficRecordedDeadline) {
					t.Fatal("bounded exact-target traffic", err)
				}
				measurement.TrafficEndedAtDeadline = true
				t.Logf("incomplete bounded traffic retained: batches=%d bytes=%d; checking actual near-full artifact without another attempt", measurement.Traffic.Batches, measurement.Traffic.Bytes)
			}
		}
	}
	continuation := map[string]any{"preview_id": preview.ID, "idempotency_key": original["idempotency_key"], "continue_acquisition": true}
	resolution := map[string]any{"preview_id": preview.ID, "idempotency_key": original["idempotency_key"]}
	initialStoragePreview = preview.ID
	initialCode := requestCapture(original)
	// ADR-277: nothing was accepted while storage refreshed; the contract
	// asks for a same-key retry, never a resolution that closes the intent.
	for retries := 0; initialCode == "StorageRefreshing" && retries < 5; retries++ {
		t.Logf("approved submission storage refreshing; same-key retry %d", retries+1)
		if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
			t.Fatal(err)
		}
		initialCode = requestCapture(original)
	}
	t.Logf("approved submission initial public code=%q", initialCode)
	closed, err := installedJourneyRecoverCapture(ctx, initialCode, func() (installedJourneyDisposition, error) {
		var disposition installedJourneyDisposition
		read("resolve_capture_request", resolution, &disposition)
		t.Logf("approved submission resolution state=%q", disposition.State)
		if disposition.State == "accepted" {
			receipt.CaptureID = disposition.CaptureID
		}
		return disposition, nil
	}, func() (string, string) { code := requestCapture(continuation); return code, receipt.CaptureID }, func() error {
		var disposition installedJourneyDisposition
		read("resolve_capture_request", resolution, &disposition)
		if receipt.CaptureID == "" || disposition.State != "accepted" || disposition.CaptureID != receipt.CaptureID {
			return errors.New("original approved request was not accepted once")
		}
		return nil
	}, installedJourneyPause, func(id string) (installedJourneyCaptureProgress, error) {
		var current installedJourneyCaptureProgress
		read("get_capture", map[string]string{"capture_id": id}, &current)
		observeTraffic(current, id)
		return current, nil
	})
	if err != nil || closed || receipt.CaptureID == "" {
		diagnose()
		t.Fatal("approved expired-preview submission", "initial code", initialCode, "closed", closed, "error", err)
	}
	initialStoragePreview = ""
	originalID := receipt.CaptureID
	confirmReplay := func() {
		if code := requestCapture(original); code != "" || receipt.CaptureID != originalID {
			t.Fatal("approved replay changed original capture", code)
		}
		for _, otherClient := range []*installedBrowser{self, browser} {
			if code := browserCall(otherClient, "request_capture", original, nil); code != "NotAvailable" && code != "ReviewChanged" {
				t.Fatal("known key leaked another actor/client accepted replay", code)
			}
		}
	}
	if measurement == nil {
		confirmReplay()
	}
	until := time.Now().Add(3 * time.Minute)
	var progress installedJourneyCaptureProgress
	for time.Now().Before(until) {
		read("get_capture", map[string]string{"capture_id": receipt.CaptureID}, &progress)
		observeTraffic(progress, originalID)
		ready, err := installedJourneyCaptureCaseReady(ctx, receipt.CaptureID, progress)
		if err != nil {
			diagnose()
			t.Fatal(err)
		}
		if ready {
			break
		}
		if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if !trafficAttempted || progress.Phase != "Succeeded" || progress.CaseID == "" {
		diagnose()
		t.Fatal("real recording did not publish", progress)
	}
	if measurement != nil {
		confirmReplay()
	}
	var evidence struct {
		Artifacts []struct {
			ID                 string                               `json:"artifact_id"`
			DataClass          string                               `json:"data_class"`
			Kind               string                               `json:"kind"`
			Digest             string                               `json:"digest"`
			NativeFormat       string                               `json:"native_format"`
			Expires            time.Time                            `json:"expires_at"`
			Target             presentation.ContextCaseTargetData   `json:"target"`
			ProfileAcquisition *presentation.ProfileAcquisitionData `json:"profile_acquisition"`
		} `json:"artifacts"`
	}
	read("get_case", map[string]string{"case_id": progress.CaseID}, &evidence)
	if installedJourneyFocus() == "manual-mixed" {
		// ADR-276: one case holds both recordings; each downloads natively.
		if len(evidence.Artifacts) != 2 {
			t.Fatal("composition group did not publish both recordings", evidence)
		}
		formats := map[string]bool{}
		for n, a := range evidence.Artifacts {
			var packetMCP, packetBrowser *analysis.PacketSummary
			if a.NativeFormat == artifact.PCAPNGFormat {
				if a.DataClass != "metadata" || a.Kind != "packetCapture" || a.Target.PodUID != preview.Pods[0].UID || a.Target.ClusterID != cluster || a.Target.Namespace != namespace || a.Target.WorkloadName != workload {
					t.Fatal("mixed packet source changed original metadata target")
				}
				source := installedPacketSummarySource{CaseID: progress.CaseID, ArtifactID: a.ID, Version: a.Digest, PodUID: preview.Pods[0].UID, Expires: a.Expires}
				mcp := queryInstalledPacketSummary(t, ctx, identity, transport, origin, source, summaryCheck)
				console := queryInstalledPacketSummaryBrowser(t, ctx, self, address, source, summaryCheck)
				packetMCP, packetBrowser = &mcp, &console
			}
			native, extension := installedMixedDownload(t, ctx, transport, identity, origin, a.ID, "installed-mixed-download-"+strconv.Itoa(n), invoke, read, diagnose)
			formats[extension] = true
			if extension == ".pcapng" {
				path := "../results/manual-mixed.pcapng"
				if err := os.WriteFile(path, native, 0600); err != nil {
					t.Fatal(err)
				}
				if packetMCP == nil || packetBrowser == nil {
					t.Fatal("mixed packet source was not summarized before native download")
				}
				installedPacketSummaryTshark(t, ctx, path, native, *packetMCP, *packetBrowser)
			} else if len(native) > 0 {
				var first struct {
					Identity struct {
						PodUID string `json:"pod_uid"`
					} `json:"identity"`
				}
				if json.Unmarshal(native[:bytes.IndexByte(native, '\n')+1], &first) != nil || first.Identity.PodUID != preview.Pods[0].UID {
					t.Fatal("mixed syscall recording names another Pod")
				}
				t.Logf("mixed syscall recording: %d metadata events", ongoingSyscallEvents(t, native, first.Identity.PodUID, time.Now()))
			}
		}
		if !formats[".pcapng"] || !formats[".jsonl"] {
			t.Fatal("composition group recordings lack a format", formats)
		}
		return
	}
	if len(evidence.Artifacts) != 1 || evidence.Artifacts[0].Expires.Before(submitted.Add(590*time.Second)) || evidence.Artifacts[0].Expires.After(time.Now().Add(600*time.Second)) {
		t.Fatal("manual recording retention did not start at submission", evidence)
	}
	wantClass := "metadata"
	if installedJourneyFocus() == "manual-raw" || installedProfileFocus() || installedJourneyFocus() == "manual-arguments" {
		wantClass = "raw"
	}
	if installedJourneyFocus() == "manual-http" {
		wantClass = "extract"
	}
	wantProfileFormat := "pprof"
	if installedProfileFocus() && installedRuntimeTraceVariant() {
		wantProfileFormat = "go-trace"
	}
	if installedProfileFocus() && (evidence.Artifacts[0].Kind != "profile" || evidence.Artifacts[0].NativeFormat != wantProfileFormat) {
		t.Fatal("published profile is mislabeled", evidence.Artifacts[0].Kind)
	}
	if evidence.Artifacts[0].DataClass != wantClass {
		t.Fatal("case lists the recording with another data class", evidence.Artifacts[0].DataClass, wantClass)
	}
	if installedProfileFocus() && installedRuntimeTraceVariant() {
		qualifyRuntimeTraceCase(t, evidence.Artifacts[0].Target, evidence.Artifacts[0].ProfileAcquisition, cluster, namespace, workload, preview.Pods[0].UID, preview.Pods[0].Name)
		if len(profileCapture) != 1 || profileCapture[0].NoQueries == nil {
			t.Fatal("trace query-absence SQL evidence missing")
		}
		profileCapture[0].NoQueries(receipt.CaptureID, evidence.Artifacts[0].ID)
		qualifyRuntimeTraceSummaryDenied(t, ctx, identity, transport, origin, progress.CaseID, evidence.Artifacts[0].ID)
		profileCapture[0].NoQueries(receipt.CaptureID, evidence.Artifacts[0].ID)
	}
	if installedProfileFocus() && installedHeapProfileVariant() {
		row := evidence.Artifacts[0]
		facts := row.ProfileAcquisition
		if row.Target.ClusterID != cluster || row.Target.Namespace != namespace || row.Target.WorkloadName != workload || row.Target.PodUID != preview.Pods[0].UID || (row.Target.PodName != "" && row.Target.PodName != preview.Pods[0].Name) || facts == nil || facts.RequestedType != "heap" || facts.Mode != "snapshot" || facts.RequestedDurationMillis != nil || facts.ForceGC || facts.StartedAt == nil || facts.CompletedAt == nil || facts.CompletedAt.Before(*facts.StartedAt) || facts.ClockUncertaintyMillis != nil || facts.ProcessAttribution != "unknown" {
			t.Fatalf("heap acquisition lost the approved original target/snapshot parameters: target=%+v profile=%+v", row.Target, facts)
		}
		if summaryCheck == nil {
			t.Fatal("heap browser requires independent SQL summary check")
		}
		verify := summaryCheck(row.ID)
		var ownedHandle, ownedOperation string
		checked := false
		// Register failure proof before browser ownership; deferred browser close
		// joins first, including failures after an early pending event.
		defer func() {
			if ownedHandle != "" && !checked {
				verify(ownedHandle, ownedOperation)
			}
		}()
		call, downloadNative, finishBrowser := installedProfileBrowser(t, ctx, self, address, installedProfileComparisonSource{CaseID: progress.CaseID, ArtifactID: row.ID, Version: row.Digest, Expires: row.Expires}, "heap", func(reply installedComparisonReply) {
			if ownedOperation == "" {
				ownedOperation = reply.RequestID
			}
			if reply.Status == "pending" && ownedHandle == "" {
				var pending struct {
					Handle string `json:"query_handle"`
				}
				if json.Unmarshal(reply.Data, &pending) == nil {
					ownedHandle = pending.Handle
				}
			}
		})
		defer finishBrowser()
		heapSummary := queryInstalledProfileSummary(t, ctx, identity, transport, origin, progress.CaseID, row.ID, row.Digest, "inuse_space", row.Expires, func(string) func(string, string) func() {
			return func(handle, operation string) func() {
				if handle != "" {
					checked = true
				}
				return verify(handle, operation)
			}
		}, call)
		if heapSummary.Unit != "bytes" || heapSummary.DurationSeconds != nil || heapSummary.Total <= 0 {
			t.Fatal("heap snapshot summary invented duration or lost allocation bytes", heapSummary)
		}
		t.Log("heap phase: installed React summary completed with joined SQL worker/key proof; read-only MCP native preparation denied, no native preparation admitted yet; console is the explicitly reviewed result client")
		t.Log("heap phase: separately authorized browser native preparation begins after the joined summary")
		native, _ := downloadNative()
		finishBrowser()
		qualifyManualHeapNative(t, ctx, native, receipt.CaptureID)
		if err := installedProfileSummaryMatchesNative(heapSummary, native, "main.main"); err != nil {
			t.Fatal("browser heap summary differs from authenticated browser native original", err)
		}
		qualifyManualRecorderRepeatPreview(t, receipt.CaptureID, preview, invoke, diagnose)
		t.Log("installed heap snapshot: namespace profile, independent collection review selecting only console result access, original Pod, no forced GC; real installed React untouched inuse_space default, one summary before one authenticated browser attachment; exact signed native total/bytes and null duration, MCP fresh repeat verified")
		return
	}
	var rawSummaries []analysis.PacketSummary
	var rawQueries []analysis.PacketQueryResult
	if installedJourneyFocus() == "manual-raw" {
		row := evidence.Artifacts[0]
		if row.Kind != "packetCapture" || row.NativeFormat != artifact.RawPCAPNGFormat || row.Target.PodUID != preview.Pods[0].UID || row.Target.ClusterID != cluster || row.Target.Namespace != namespace || row.Target.WorkloadName != workload {
			t.Fatal("raw summary source changed original raw target")
		}
		source := installedPacketSummarySource{CaseID: progress.CaseID, ArtifactID: row.ID, Version: row.Digest, PodUID: preview.Pods[0].UID, Expires: row.Expires, CaptureMode: "rawPackets"}
		rawSummaries = append(rawSummaries, queryInstalledPacketSummary(t, ctx, identity, transport, origin, source, summaryCheck))
		rawSummaries = append(rawSummaries, queryInstalledPacketSummaryBrowser(t, ctx, self, address, source, summaryCheck))
		t.Log("raw summary phase: independent read-only MCP and installed React fixed extracts completed before separately authorized original raw download")
		if packetQueryDrain == nil {
			t.Fatal("raw four-query original-worker pipeline missing")
		}
		packetQueryDrain() // Original first summary ends before a third worker is admitted.
		querySource := installedPacketQuerySource{CaseID: progress.CaseID, ArtifactID: row.ID, Version: row.Digest, PodUID: preview.Pods[0].UID, GrantID: grantID, Expires: row.Expires}
		rawQueries = append(rawQueries, queryInstalledPacketQuery(t, ctx, identity, transport, origin, querySource, packetQueryCheck))
		packetQueryDrain() // Original second summary ends before the fourth worker.
		rawQueries = append(rawQueries, queryInstalledPacketQueryBrowser(t, ctx, self, address, querySource, installedPacketQueryRequest(querySource, "installed-packet-query-console-"+row.ID), packetQueryCheck))
		packetQueryDrain()
		packetQueryDrain() // Both query results were delivered before their original terminal waits.
		t.Log("raw packet query phase: MCP and actual React pages use the original combined review, same-source grant children and separately charged disclosures; no new acquisition before native download")
	}
	if measurement != nil {
		if err := finishRecording(); err != nil {
			t.Fatal(err)
		}
	}
	var download installedJourneyDownload
	prepare := map[string]string{"artifact_id": evidence.Artifacts[0].ID, "idempotency_key": "installed-approved-download-" + evidence.Artifacts[0].ID}
	// Preparation is an effect: no automatic retry after an uncertain reply
	// or acknowledged failure. Only the server's continuation flag below
	// permits another exact same-key prepare, as in the original journey.
	prepareDownload := func() {
		t.Helper()
		reply, code := invoke("prepare_artifact_download", prepare)
		if code != "" || reply.Status != "ok" || json.Unmarshal(reply.Data, &download) != nil {
			diagnose()
			t.Fatal("initial or acknowledged download preparation failed", code)
		}
	}
	var finishPrepare func() error
	if measurement != nil {
		finishPrepare, err = measurement.begin(ctx, "prepare-unpaced")
		if err != nil {
			t.Fatal(err)
		}
	}
	prepareDownload()
	downloadID, deadline := download.DownloadID, download.ExpiresAt
	if downloadID == "" || deadline.IsZero() || !time.Now().Before(deadline) || deadline.After(evidence.Artifacts[0].Expires) {
		t.Fatal("native download exceeds original evidence deadline")
	}
	for download.State == "Preparing" && time.Now().Before(until) {
		if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
			t.Fatal(err)
		}
		if download.ContinuePreparation {
			prepareDownload()
		} else {
			read("get_artifact_download", map[string]string{"download_id": downloadID}, &download)
		}
		if download.DownloadID != downloadID || !download.ExpiresAt.Equal(deadline) {
			t.Fatal("native download identity/deadline changed")
		}
	}
	nativeLimit := int64(artifact.RecordingNativeLimit)
	if installedProfileFocus() {
		nativeLimit = artifact.MaxPprofBytes
		if installedRuntimeTraceVariant() {
			nativeLimit = 32 << 20
		}
	}
	if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil || *download.SizeBytes < 1 || *download.SizeBytes > nativeLimit {
		diagnose()
		t.Fatal("approved recording native download not ready", download.State)
	}
	var finishUnpaced func() error
	if measurement != nil {
		if err := finishPrepare(); err != nil {
			t.Fatal(err)
		}
		finishUnpaced, err = measurement.begin(ctx, "unpaced")
		if err != nil {
			t.Fatal(err)
		}
	}
	unpacedStarted := time.Now()
	response := installedJourneyContent(t, ctx, &http.Client{Transport: transport, Timeout: time.Minute}, strings.TrimSuffix(origin, "/")+download.ContentPath, identity.downloadToken(), nil)
	_, disposition, dispositionErr := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	extension := ".pcapng"
	if installedProfileFocus() {
		extension = ".pb.gz"
		if installedRuntimeTraceVariant() {
			extension = ".trace"
		}
	}
	if installedJourneyFocus() == "manual-syscall" || installedJourneyFocus() == "manual-arguments" {
		extension = ".jsonl"
	}
	if installedJourneyFocus() == "manual-http" {
		extension = manualHTTPExtension(t)
	}
	if dispositionErr != nil || disposition["filename"] != "artifact-"+evidence.Artifacts[0].ID+extension {
		response.Body.Close()
		diagnose()
		t.Fatal("native download lacks its expected filename", response.StatusCode, dispositionErr)
	}
	native, err := io.ReadAll(io.LimitReader(response.Body, nativeLimit+1))
	response.Body.Close()
	digest := sha256.Sum256(native)
	if err != nil || response.StatusCode != http.StatusOK || int64(len(native)) != *download.SizeBytes || hex.EncodeToString(digest[:]) != download.SHA256 {
		t.Fatal("native artifact does not match authenticated metadata", err)
	}
	if measurement != nil {
		if response.ProtoMajor != 2 || response.ContentLength != int64(len(native)) || response.Header.Get("ETag") != download.ETag {
			t.Fatal("unpaced HTTP/2 control metadata mismatch")
		}
		measurement.Bodies = map[string]nativePacingResult{"unpaced": {Bytes: int64(len(native)), SHA256: digest, Elapsed: time.Since(unpacedStarted)}}
		if err := finishUnpaced(); err != nil {
			t.Fatal(err)
		}
	}
	if installedJourneyFocus() == "manual-arguments" {
		qualifyManualArgumentsNative(t, native, receipt.CaptureID, preview.Pods[0].UID, argumentSource)
		if evidence.Artifacts[0].Kind != "syscallTrace" || evidence.Artifacts[0].NativeFormat != "asservat-syscall-arguments/v1" {
			t.Fatal("argument artifact native classification", evidence.Artifacts[0])
		}
		retirement, err := finishInstalledSyscallNativeDownload(downloadID, invoke, stoppedDownload)
		if err != nil {
			t.Fatal(err)
		}
		if packetQueryCheck == nil || packetQueryDrain == nil {
			t.Fatal("raw argument query proof pipeline missing")
		}
		row := evidence.Artifacts[0]
		source := installedSyscallQueryBrowserSource{CaseID: progress.CaseID, ArtifactID: row.ID, Version: row.Digest, PodUID: preview.Pods[0].UID, GrantID: grantID, Expires: row.Expires}
		qualifyInstalledSyscallProjections(t, ctx, identity, transport, origin, progress.CaseID, row.ID, row.Digest, artifact.SyscallArgumentsArtifact, preview.Pods[0].UID, native, row.Expires, manualArgumentsMarker, summaryCheck, retirement, installedSyscallQueryContinuation{BeforeQuery: packetQueryDrain, RawQueries: func(afterEach func()) {
			packetQueryDrain()
			mcp := queryInstalledRawSyscalls(t, ctx, identity, transport, origin, source, packetQueryCheck)
			afterEach()
			packetQueryDrain()
			console := queryInstalledRawSyscallsBrowser(t, ctx, self, address, source, packetQueryCheck)
			afterEach()
			qualifyInstalledRawSyscallParity(t, native, source, mcp, console)
		}})
		qualifyManualRecorderRepeatPreview(t, receipt.CaptureID, preview, invoke, diagnose)
		qualifyManualRecorderStop(t, ctx, "arguments", manualArgumentsCaptureInput(cluster, namespace, workload, true), read, invoke, func(grantID string) {
			browser.approvedRecordingStepUp(t, ctx, reviewer, grantID)
			if code := browserCall(browser, "decide_review", map[string]any{"grant_id": grantID, "decision": "approve", "reason": "independent installed argument Stop review", "idempotency_key": "approve-stop-" + grantID}, nil); code != "" {
				t.Fatal("Stop argument independent approval", code)
			}
		})
		return
	}
	if installedProfileFocus() {
		if installedRuntimeTraceVariant() {
			qualifyManualRuntimeTraceNative(t, ctx, native, receipt.CaptureID)
			profileCapture[0].NoQueries(receipt.CaptureID, evidence.Artifacts[0].ID)
			qualifyManualRecorderRepeatPreview(t, receipt.CaptureID, preview, invoke, diagnose)
			return
		}
		qualifyManualProfileNative(t, ctx, native, receipt.CaptureID)
		if installedJourneyFocus() == "profile-comparison" {
			retirement, err := finishInstalledSyscallNativeDownload(downloadID, invoke, stoppedDownload)
			if err != nil {
				t.Fatal(err)
			}
			profileCapture[0].Captured(transport, installedProfileComparisonSource{CaseID: progress.CaseID, ArtifactID: evidence.Artifacts[0].ID, Version: evidence.Artifacts[0].Digest, Native: native, Expires: evidence.Artifacts[0].Expires, Retirement: retirement})
			return
		}
		qualifyManualRecorderRepeatPreview(t, receipt.CaptureID, preview, invoke, diagnose)
		qualifyInstalledProfileSummary(t, ctx, identity, transport, origin, progress.CaseID, evidence.Artifacts[0].ID, evidence.Artifacts[0].Digest, native, evidence.Artifacts[0].Expires, summaryCheck)
		if len(profileCapture) != 1 || profileCapture[0].Refused == nil {
			t.Fatal("manual profile refusal SQL evidence is unavailable")
		}
		if installedTLSProfileTransport() {
			if installedProfileAuthorization() {
				qualifyManualProfileAuthorization(t, ctx, region, namespace, preview.Pods[0].Name, preview.Pods[0].UID, regionalConfig, cluster, workload, native, []any{preview, progress, evidence}, invoke)
			}
			qualifyManualProfileTLSWrongPeer(t, ctx, region, namespace, preview.Pods[0].Name, preview.Pods[0].UID, regionalConfig, cluster, workload, read, readContext, invoke, func(grantID string) {
				browser.approvedRecordingStepUp(t, ctx, reviewer, grantID)
				if code := browserCall(browser, "decide_review", map[string]any{"grant_id": grantID, "decision": "approve", "reason": "independent wrong TLS peer qualification review", "idempotency_key": "approve-tls-refusal-" + grantID}, nil); code != "" {
					t.Fatal("TLS negative independent approval", code)
				}
			}, profileCapture[0].Refused)
			t.Log("TLS CPU positive: encrypted publication, authenticated pprof, read-only summary and fresh repeat preview; CPU busy/missing/Stop branches are separate HTTP qualification")
			return
		}
		qualifyManualProfileRefusals(t, ctx, region, namespace, preview.Pods[0].Name, preview.Pods[0].UID, manualProfileArguments(cluster, namespace, workload), read, readContext, invoke, func(grantID string) {
			browser.approvedRecordingStepUp(t, ctx, reviewer, grantID)
			if code := browserCall(browser, "decide_review", map[string]any{"grant_id": grantID, "decision": "approve", "reason": "independent installed profile refusal review", "idempotency_key": "approve-profile-refusal-" + grantID}, nil); code != "" {
				t.Fatal("profile refusal independent approval", code)
			}
		}, profileCapture[0].Refused)
		qualifyManualRecorderStop(t, ctx, "profile", manualProfileStopArguments(cluster, namespace, workload), read, invoke, func(grantID string) {
			browser.approvedRecordingStepUp(t, ctx, reviewer, grantID)
			if code := browserCall(browser, "decide_review", map[string]any{"grant_id": grantID, "decision": "approve", "reason": "independent installed profile Stop review", "idempotency_key": "approve-stop-" + grantID}, nil); code != "" {
				t.Fatal("Stop profile independent approval", code)
			}
		})
		return
	}
	if installedJourneyFocus() == "manual-syscall" {
		// B3: metadata-only JSON Lines of the one recorded Pod.
		var first struct {
			Identity struct {
				PodUID string `json:"pod_uid"`
			} `json:"identity"`
		}
		if err := os.WriteFile("../results/manual-syscall.jsonl", native, 0600); err != nil || json.Unmarshal(native[:bytes.IndexByte(native, '\n')+1], &first) != nil || first.Identity.PodUID == "" {
			t.Fatal("manual syscall recording has no readable first event", err)
		}
		events := ongoingSyscallEvents(t, native, first.Identity.PodUID, time.Now())
		t.Logf("manual syscall recording %s: %d metadata events, %d bytes", receipt.CaptureID, events, len(native))
		retirement, err := finishInstalledSyscallNativeDownload(downloadID, invoke, stoppedDownload)
		if err != nil {
			t.Fatal(err)
		}
		qualifyInstalledSyscallProjections(t, ctx, identity, transport, origin, progress.CaseID, evidence.Artifacts[0].ID, evidence.Artifacts[0].Digest, artifact.SyscallRecordsArtifact, first.Identity.PodUID, native, evidence.Artifacts[0].Expires, "", summaryCheck, retirement)
		return
	}
	if installedJourneyFocus() == "manual-http" {
		s := qualifyManualHTTPProjection(t, native)
		t.Logf("manual HTTP header recording %s: %d records (%d GET with status), %d bytes; counters %+v", receipt.CaptureID, s.Records, s.Answered, len(native), s.Counters)
		qualifyManualHTTPQuery(t, ctx, session, wire, progress.CaseID, evidence.Artifacts[0].ID, native, diagnose)
		return
	}
	if installedJourneyFocus() == "manual-peers" {
		packets := qualifyManualPeersPCAP(t, ctx, native, peerIPs[0])
		t.Logf("manual peer recording %s: %d packets, all to or from peer %s on port %d, %d bytes", receipt.CaptureID, packets, peerIPs[0], manualPeersPort, len(native))
		return
	}
	if installedJourneyFocus() == "manual-raw" {
		s := qualifyManualRawPCAP(t, ctx, native)
		if len(rawSummaries) != 2 || !bytes.Contains(native, []byte("synthetic-approved-recording")) {
			t.Fatal("raw original lacks both summaries or actual payload marker")
		}
		for _, summary := range rawSummaries {
			encoded, _ := json.Marshal(summary)
			if bytes.Contains(encoded, []byte("synthetic-approved-recording")) {
				t.Fatal("raw payload marker escaped fixed summary")
			}
		}
		installedPacketSummaryTshark(t, ctx, "../results/manual-raw.pcapng", native, rawSummaries...)
		if len(rawQueries) != 2 {
			t.Fatal("both original raw packet query clients missing")
		}
		installedPacketQueryTshark(t, ctx, "../results/manual-raw.pcapng", native, rawQueries...)
		t.Logf("manual raw recording %s: %d packets on port 8080, %d kept payload beyond %d header bytes, largest %d (cap %d), %d bytes", receipt.CaptureID, s.Packets, s.Payload, artifact.RecordingSnaplen, s.MaxCaptured, manualRawTCPCap, len(native))
		return
	}
	path := "../results/approved-recording" + installedFocusKeySuffix() + ".pcapng"
	if err := os.WriteFile(path, native, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := installedOutput(ctx, installedLocalToolTimeout, "tshark", "-r", path, "-T", "fields", "-e", "tcp.port")
	if err != nil {
		t.Fatal("native PCAPNG did not open in tshark", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("native PCAPNG has no real captured traffic")
	}
	for _, line := range lines {
		if !strings.Contains(line, "8080") {
			t.Fatalf("native packet outside reviewed port: %q", line)
		}
	}
	if measurement != nil {
		stats, err := installedOutput(ctx, installedLocalToolTimeout, "capinfos", "-M", "-I", path)
		if err != nil || len(stats) == 0 || len(stats) > 65536 {
			t.Fatal("native PCAPNG interface statistics unavailable", err)
		}
		measurement.PCAPInterfaceStatistics = string(stats)
		timestamps, err := installedOutput(ctx, installedLocalToolTimeout, "tshark", "-r", path, "-T", "fields", "-e", "frame.time_epoch")
		if err != nil || len(timestamps) > 16<<20 {
			t.Fatal("native packet timestamps unavailable", err)
		}
		for _, value := range strings.Fields(string(timestamps)) {
			seconds, err := strconv.ParseFloat(value, 64)
			if err != nil || seconds <= 0 {
				t.Fatal("native packet timestamp invalid")
			}
			at := time.Unix(0, int64(seconds*1e9)).UTC()
			if measurement.FirstPacketAt.IsZero() || at.Before(measurement.FirstPacketAt) {
				measurement.FirstPacketAt = at
			}
			if at.After(measurement.LastPacketAt) {
				measurement.LastPacketAt = at
			}
			if !at.Before(measurement.TrafficStartedAt) && !at.After(measurement.TrafficFinishedAt) {
				measurement.PacketsDuringTraffic++
			}
		}
		if measurement.PacketsDuringTraffic == 0 {
			t.Fatal("native PCAPNG has no measured traffic overlap")
		}
	}
	// Retain authenticated content, statistics and window proof even when the
	// unchanged size guard refuses an underfilled recording. NearFullBytes is
	// success-only; a retained small file never qualifies the paced comparison.
	if measurement != nil {
		if err := nativePacingRequireNearFullRecording(*download.SizeBytes); err != nil {
			t.Fatal(err)
		}
		measurement.NearFullBytes = *download.SizeBytes
		qualifyInstalledNativePacing(t, ctx, measurement, transport, identity, origin, evidence.Artifacts[0].ID, download, native, invoke, callOnce, read, diagnose)
	}
	var finishChecks func() error
	if measurement != nil {
		finishChecks, err = measurement.begin(ctx, "joined-cleanup")
		if err != nil {
			t.Fatal(err)
		}
	}
	// This history branch qualifies the repeat in the canonical recording focus.
	// Other focuses (including paced delivery) retain their own scope.
	// The original requester browser creates a new
	// repeat; the separate reviewer only authenticates and decides its new grant.
	if installedJourneyFocus() == "approved-recording" {
		historyPhase(receipt.CaptureID)
		qualifyInstalledRecorderHistory(t, ctx, self, address, arguments["target_ref"].(map[string]string), receipt.CaptureID, grantID, invoke, func(captureID string) { historyPhase(captureID); diagnose() }, func(approvalCtx context.Context, repeatGrant string) {
			browser.approvedRecordingStepUp(t, approvalCtx, reviewer, repeatGrant)
			if code := browserCallCurrent(approvalCtx, browser, "decide_review", map[string]any{"grant_id": repeatGrant, "decision": "approve", "reason": "independent installed edited history repeat", "idempotency_key": "installed-history-approval-" + repeatGrant}, nil); code != "" {
				t.Fatal("signed independent history decision", code)
			}
			var decision struct {
				Phase    string `json:"phase"`
				Decision struct {
					By struct {
						Subject string `json:"subject"`
					} `json:"decided_by"`
				} `json:"decision"`
			}
			if code := browserCallCurrent(approvalCtx, browser, "get_grant", map[string]string{"grant_id": repeatGrant}, &decision); code != "" || decision.Phase != "Approved" || decision.Decision.By.Subject != reviewer.ReviewerSubject {
				t.Fatal("history decision did not retain independent signed subject", code)
			}
		})
	}
	// A closed preview is one finished intent even when its key is public.
	// A different key cannot reopen it or cause another approval/capture.
	var closedPreview struct {
		ID string `json:"preview_id"`
	}
	read("preview_capture", arguments, &closedPreview)
	closeRequest := map[string]string{"preview_id": closedPreview.ID, "idempotency_key": "approved-preview-" + closedPreview.ID}
	var closedIntent installedJourneyDisposition
	read("resolve_capture_request", closeRequest, &closedIntent)
	if closedIntent.State != "closed" {
		t.Fatal("fresh original intent did not close")
	}
	if _, code := invoke("request_capture", map[string]string{"preview_id": closedPreview.ID, "idempotency_key": "another-key-cannot-revive-closed-preview" + installedFocusKeySuffix()}); code != "ReviewChanged" && code != "NotAvailable" {
		t.Fatal("closed public intent became a fresh start", code)
	}
	if measurement != nil {
		if err := finishChecks(); err != nil {
			t.Fatal(err)
		}
		measurement.Complete = true
	}
	report := map[string]any{"captureID": receipt.CaptureID, "grantID": grantID, "previewID": preview.ID, "executionDigest": preview.Digest, "independentReviewerSubject": reviewer.ReviewerSubject, "previewExpiresAt": preview.Expires, "submittedAt": submitted, "remainingRealWaitSeconds": realWait.Seconds(), "nativeSHA256": hex.EncodeToString(digest[:]), "nativeBytes": len(native), "tsharkPackets": len(lines), "assurance": "real signed Keycloak fresh password LoA1, not MFA", "authorization": "public product request/decision/admission; no fixture grant rows"}
	raw, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile("../results/approved-recording"+installedFocusKeySuffix()+"-report.json", append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("independent approved exact preview submitted after real expiry; %d native PCAPNG packets/%d bytes verified in tshark", len(lines), len(native))
}

// installedMixedDownload prepares, awaits and reads one native artifact of
// the manual-mixed focus, returning its bytes and its filename extension.
func installedMixedDownload(t *testing.T, ctx context.Context, transport http.RoundTripper, identity *installedIdentity, origin, artifactID, key string, invoke func(string, any) (installedJourneyEnvelope, string), read func(string, any, any), diagnose func()) ([]byte, string) {
	t.Helper()
	return installedNativeDownload(t, ctx, transport, identity, origin, artifactID, key, invoke, read, diagnose, ".pcapng", ".jsonl")
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
