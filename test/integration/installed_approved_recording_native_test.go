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
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// approvedRecordingArguments is the actual public request, validated offline
// before the expensive installed qualification. It is never authority.
func approvedRecordingArguments(cluster, namespace, workload string) map[string]any {
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

// This focus uses the ordinary product installer and official chart. Its only
// privileged component runs on a guarded disposable runner, never a workstation.
func installApprovedRecordingCollector(t *testing.T, ctx context.Context, api kubernetes.Interface, config, image, installation, cluster string) {
	t.Helper()
	if _, err := os.Stat("/etc/asservat-disposable-host"); err != nil {
		t.Fatal("approved collector requires disposable host", err)
	}
	if image == "" {
		t.Fatal("approved collector lacks built image")
	}
	source, err := api.CoreV1().ConfigMaps("asservat-connector").Get(ctx, kube.RegionalNodes, meta.GetOptions{})
	if err != nil {
		t.Fatal("installed collector endpoint", err)
	}
	values := map[string]any{"mode": "cluster", "collector": map[string]any{"enabled": true, "image": image, "installationID": installation, "clusterID": cluster, "connector": source.Data}}
	raw, _ := json.Marshal(values)
	path := filepath.Join(t.TempDir(), "collector-values.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	render := exec.CommandContext(ctx, "helm", "template", "asservat", "../../charts/asservat", "--namespace", "asservat-region", "--kube-version", "1.37.0", "-f", path)
	manifest, err := render.Output()
	if err != nil {
		t.Fatal("official collector chart", err)
	}
	apply := exec.CommandContext(ctx, "kubectl", "--kubeconfig", config, "apply", "-f", "-")
	apply.Stdin = bytes.NewReader(manifest)
	if out, err := apply.CombinedOutput(); err != nil {
		t.Fatalf("collector apply: %v %s", err, out)
	}
	roll := exec.CommandContext(ctx, "kubectl", "--kubeconfig", config, "-n", "asservat-collector", "rollout", "status", "daemonset/asservat-node", "--timeout=90s")
	if out, err := roll.CombinedOutput(); err != nil {
		t.Fatalf("collector readiness: %v %s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			c, end := context.WithTimeout(context.Background(), 10*time.Second)
			defer end()
			out, _ := exec.CommandContext(c, "kubectl", "--kubeconfig", config, "-n", "asservat-collector", "logs", "-l", "app.kubernetes.io/name=asservat-node", "--tail=100", "--prefix").CombinedOutput()
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

func qualifyInstalledApprovedRecording(t *testing.T, ctx context.Context, identity *installedIdentity, publicRoot []byte, address, origin, cluster, namespace, workload, regionalConfig string, diagnose func()) {
	t.Helper()
	if _, err := os.Stat("/etc/asservat-disposable-host"); err != nil {
		t.Fatal("approved recording requires disposable runner", err)
	}
	cert, err := x509.ParseCertificate(publicRoot)
	if err != nil {
		t.Fatal(err)
	}
	identity.initializeProcessing(t, ctx, cert, address, origin, diagnose)
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
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, tokens.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	invoke := func(name string, args any) (installedJourneyEnvelope, string) {
		t.Helper()
		call, end := context.WithTimeout(ctx, 45*time.Second)
		defer end()
		result, err := session.CallTool(call, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			diagnose()
			t.Fatal("approved recording MCP", name, err)
		}
		reply, code, err := installedJourneyReplyCode(wire, name, result)
		if err != nil {
			t.Fatal("approved recording wire", name, err)
		}
		return reply, code
	}
	read := func(name string, args, out any) {
		t.Helper()
		for attempt := 0; attempt < 4; attempt++ {
			reply, code := invoke(name, args)
			if code == "" && reply.Status == "ok" {
				if err := json.Unmarshal(reply.Data, out); err != nil {
					t.Fatal(name, err)
				}
				return
			}
			if attempt == 3 {
				diagnose()
				t.Fatal("approved recording read", name, code)
			}
			if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
				t.Fatal(err)
			}
		}
	}
	var preview struct {
		ID       string                       `json:"preview_id"`
		Expires  time.Time                    `json:"expires_at"`
		Approval bool                         `json:"approval_required"`
		Enabled  bool                         `json:"capture_enabled"`
		Digest   string                       `json:"execution_digest"`
		Pods     []struct{ UID, Name string } `json:"selected_pods"`
	}
	arguments := approvedRecordingArguments(cluster, namespace, workload)
	read("preview_capture", arguments, &preview)
	if preview.ID == "" || !preview.Approval || preview.Enabled || len(preview.Pods) != 1 || preview.Pods[0].UID == "" || !time.Now().Before(preview.Expires) {
		t.Fatal("approved recording preview lacks original production review window", preview)
	}
	original := map[string]any{"preview_id": preview.ID, "idempotency_key": "approved-preview-" + preview.ID}
	pending, code := invoke("request_capture", original)
	var refused struct {
		URI string `json:"navigation_uri"`
	}
	if code != "ApprovalRequired" || json.Unmarshal(pending.Data, &refused) != nil {
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
	browserCall := func(b *installedBrowser, name string, input, out any) string {
		t.Helper()
		key := ""
		if fields, ok := input.(map[string]any); ok {
			key, _ = fields["idempotency_key"].(string)
		}
		reply, status, err := b.operation(ctx, name, input, key)
		if err != nil || status != http.StatusOK {
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
	if code := browserCall(self, "decide_review", map[string]any{"grant_id": grantID, "decision": "approve", "reason": "self approval must fail", "idempotency_key": "installed-self-refusal"}, nil); code != "SelfApprovalRefused" {
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
	if code := browserCall(browser, "decide_review", map[string]any{"grant_id": grantID, "decision": "approve", "reason": "independent installed metadata packet review", "idempotency_key": "installed-independent-approval"}, nil); code != "" {
		diagnose()
		t.Fatal("signed independent decision", code)
	}
	var grant struct {
		Phase    string `json:"phase"`
		Digest   string `json:"execution_digest"`
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
	if code := browserCall(self, "get_grant", map[string]string{"grant_id": grantID}, &own); code != "" || own.CanResume || own.CanResolve || !own.ResumeRequiresOriginalClient {
		t.Fatal("approved original human lacks precise original-client guidance", code)
	}
	if code := browserCall(browser, "request_capture", original, nil); code != "NotAvailable" && code != "ReviewChanged" {
		t.Fatal("public predictable key transferred requester intent to reviewer", code)
	}
	waitStarted := time.Now()
	if err := installedJourneyPause(ctx, time.Until(preview.Expires.Add(20*time.Millisecond))); err != nil {
		t.Fatal(err)
	}
	if !time.Now().After(preview.Expires) {
		t.Fatal("real preview has not expired")
	}
	realWait := time.Since(waitStarted)
	// Real synthetic HTTP traffic goes through the Kubernetes Pod proxy to the
	// exact selected Pod. No replacement target or local host collector is used.
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
		for traffic.Err() == nil {
			call, end := context.WithTimeout(traffic, 2*time.Second)
			_, _ = region.CoreV1().RESTClient().Get().Namespace(namespace).Resource("pods").Name(preview.Pods[0].Name+":8080").SubResource("proxy").Suffix("log").Param("line", "synthetic-approved-recording").DoRaw(call)
			end()
			if installedJourneyPause(traffic, 100*time.Millisecond) != nil {
				return
			}
		}
	}()
	defer func() { endTraffic(); <-joined }()
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
	continuation := map[string]any{"preview_id": preview.ID, "idempotency_key": original["idempotency_key"], "continue_acquisition": true}
	closed, err := installedJourneyRecoverCapture(ctx, requestCapture(original), func() (installedJourneyDisposition, error) {
		var disposition installedJourneyDisposition
		read("resolve_capture_request", original, &disposition)
		if disposition.State == "accepted" {
			receipt.CaptureID = disposition.CaptureID
		}
		return disposition, nil
	}, func() (string, string) { code := requestCapture(continuation); return code, receipt.CaptureID }, func() error {
		var disposition installedJourneyDisposition
		read("resolve_capture_request", original, &disposition)
		if receipt.CaptureID == "" || disposition.State != "accepted" || disposition.CaptureID != receipt.CaptureID {
			return errors.New("original approved request was not accepted once")
		}
		return nil
	}, installedJourneyPause, func(id string) (installedJourneyCaptureProgress, error) {
		var current installedJourneyCaptureProgress
		read("get_capture", map[string]string{"capture_id": id}, &current)
		return current, nil
	})
	if err != nil || closed || receipt.CaptureID == "" {
		diagnose()
		t.Fatal("approved expired-preview submission", closed, err)
	}
	originalID := receipt.CaptureID
	if code := requestCapture(original); code != "" || receipt.CaptureID != originalID {
		t.Fatal("approved replay changed original capture", code)
	}
	for _, otherClient := range []*installedBrowser{self, browser} {
		if code := browserCall(otherClient, "request_capture", original, nil); code != "NotAvailable" && code != "ReviewChanged" {
			t.Fatal("known key leaked another actor/client accepted replay", code)
		}
	}
	until := time.Now().Add(3 * time.Minute)
	var progress installedJourneyCaptureProgress
	for time.Now().Before(until) {
		read("get_capture", map[string]string{"capture_id": receipt.CaptureID}, &progress)
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
	if progress.Phase != "Succeeded" || progress.CaseID == "" {
		diagnose()
		t.Fatal("real recording did not publish", progress)
	}
	var evidence struct {
		Artifacts []struct {
			ID      string    `json:"artifact_id"`
			Expires time.Time `json:"expires_at"`
		} `json:"artifacts"`
	}
	read("get_case", map[string]string{"case_id": progress.CaseID}, &evidence)
	if len(evidence.Artifacts) != 1 || evidence.Artifacts[0].Expires.Before(submitted.Add(590*time.Second)) || evidence.Artifacts[0].Expires.After(time.Now().Add(600*time.Second)) {
		t.Fatal("manual recording retention did not start at submission", evidence)
	}
	var download installedJourneyDownload
	prepare := map[string]string{"artifact_id": evidence.Artifacts[0].ID, "idempotency_key": "installed-approved-download"}
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
	if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil || *download.SizeBytes < 1 || *download.SizeBytes > artifact.RecordingNativeLimit {
		diagnose()
		t.Fatal("approved recording native download not ready", download.State)
	}
	response := installedJourneyContent(t, ctx, &http.Client{Transport: transport, Timeout: time.Minute}, strings.TrimSuffix(origin, "/")+download.ContentPath, identity.downloadToken(), nil)
	_, disposition, dispositionErr := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	if dispositionErr != nil || disposition["filename"] != "artifact-"+evidence.Artifacts[0].ID+".pcapng" {
		response.Body.Close()
		t.Fatal("native download lacks its PCAPNG filename", dispositionErr)
	}
	native, err := io.ReadAll(io.LimitReader(response.Body, artifact.RecordingNativeLimit+1))
	response.Body.Close()
	digest := sha256.Sum256(native)
	if err != nil || response.StatusCode != http.StatusOK || int64(len(native)) != *download.SizeBytes || hex.EncodeToString(digest[:]) != download.SHA256 {
		t.Fatal("native PCAPNG does not match authenticated metadata", err)
	}
	path := "../results/approved-recording.pcapng"
	if err := os.WriteFile(path, native, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(ctx, "tshark", "-r", path, "-T", "fields", "-e", "tcp.port").Output()
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
	if _, code := invoke("request_capture", map[string]string{"preview_id": closedPreview.ID, "idempotency_key": "another-key-cannot-revive-closed-preview"}); code != "ReviewChanged" && code != "NotAvailable" {
		t.Fatal("closed public intent became a fresh start", code)
	}
	report := map[string]any{"captureID": receipt.CaptureID, "grantID": grantID, "previewID": preview.ID, "executionDigest": preview.Digest, "independentReviewerSubject": reviewer.ReviewerSubject, "previewExpiresAt": preview.Expires, "submittedAt": submitted, "remainingRealWaitSeconds": realWait.Seconds(), "nativeSHA256": hex.EncodeToString(digest[:]), "nativeBytes": len(native), "tsharkPackets": len(lines), "assurance": "real signed Keycloak fresh password LoA1, not MFA", "authorization": "public product request/decision/admission; no fixture grant rows"}
	raw, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile("../results/approved-recording-report.json", append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("independent approved exact preview submitted after real expiry; %d native PCAPNG packets/%d bytes verified in tshark", len(lines), len(native))
}
