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
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// installedBrowser is the console's own transport: the HttpOnly session cookie
// from the real Keycloak login plus the session CSRF token and exact Origin on
// every POST, as web/src/{capture,evidence,projection}/http.ts send them. It
// holds no bearer token; the browser routes refuse Authorization headers.
type installedBrowser struct {
	t      *testing.T
	client *http.Client
	base   string
	csrf   string
	wire   *contracts.InvestigationContracts
}

// consoleSession logs the synthetic user in through the console client, like
// initializeProcessing, and keeps the cookie session for the browser journey.
func (i *installedIdentity) consoleSession(t *testing.T, ctx context.Context, publicRoot *x509.Certificate, address, origin string) *installedBrowser {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(publicRoot)
	if !roots.AppendCertsFromPEM([]byte(i.RootPEM)) {
		t.Fatal("browser journey login roots")
	}
	u, err := url.Parse(origin)
	if err != nil {
		t.Fatal("browser journey origin", err)
	}
	dial := &net.Dialer{Timeout: 5 * time.Second}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
				if host, _, e := net.SplitHostPort(target); e == nil && host == u.Hostname() {
					target = address
				}
				return dial.DialContext(ctx, network, target)
			}}}
	t.Cleanup(client.CloseIdleConnections)
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal("browser journey wire contracts", err)
	}
	b := &installedBrowser{t: t, client: client, base: strings.TrimSuffix(origin, "/"), wire: wire}
	get := func(target string) (int, []byte, http.Header) {
		t.Helper()
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal("browser journey login HTTP", e)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(response.Body, 256<<10))
		return response.StatusCode, body, response.Header
	}
	status, _, headers := get(b.base + "/auth/login?return_to=%2Finvestigations")
	if status != http.StatusSeeOther {
		t.Fatal("browser journey login start", status)
	}
	status, page, _ := get(headers.Get("Location"))
	match := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	if status != http.StatusOK || len(match) != 2 {
		t.Fatal("browser journey login form", status)
	}
	action := html.UnescapeString(string(match[1]))
	if !strings.HasPrefix(action, i.Issuer+"/login-actions/") {
		t.Fatal("browser journey login form escaped the issuer")
	}
	form, _ := http.NewRequestWithContext(ctx, http.MethodPost, action, strings.NewReader(url.Values{"username": {"developer"}, "password": {i.kc.UserPassword}}.Encode()))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(form)
	if err != nil {
		t.Fatal("browser journey provider login", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 256<<10))
	response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatal("browser journey provider login", response.StatusCode)
	}
	if status, _, _ = get(response.Header.Get("Location")); status != http.StatusSeeOther {
		t.Fatal("browser journey callback", status)
	}
	status, body, _ := get(b.base + "/api/v1/session")
	var view struct {
		CSRF string `json:"csrf_token"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &view) != nil || len(view.CSRF) != 43 {
		t.Fatal("browser journey session", status)
	}
	b.csrf = view.CSRF
	return b
}

// operation POSTs one /api/v1/operations/<name> call exactly as the console
// does and validates the reply against the shared MCP output contract: the
// browser and MCP serve one envelope. key sets the Idempotency-Key header the
// console sends for request/resolve/prepare/cancel; it must equal the body key.
// A non-200 status returns no envelope.
func (b *installedBrowser) operation(ctx context.Context, name string, input any, key string) (installedJourneyEnvelope, int, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return installedJourneyEnvelope{}, 0, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, b.base+"/api/v1/operations/"+name, bytes.NewReader(body))
	if err != nil {
		return installedJourneyEnvelope{}, 0, err
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", b.csrf)
	// A same-origin fetch POST carries these; the server requires the exact Origin.
	r.Header.Set("Origin", b.base)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	response, err := b.client.Do(r)
	if err != nil {
		return installedJourneyEnvelope{}, 0, err
	}
	defer response.Body.Close()
	// The console's own bound: 32 KiB metadata, 64 KiB approved projection.
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if err != nil {
		return installedJourneyEnvelope{}, response.StatusCode, err
	}
	if response.StatusCode != http.StatusOK {
		return installedJourneyEnvelope{}, response.StatusCode, fmt.Errorf("browser %s: HTTP %d", name, response.StatusCode)
	}
	media := strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	var out installedJourneyEnvelope
	if len(raw) > 64<<10 || media != "application/json" || b.wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil {
		b.t.Fatal("browser response contract", name)
	}
	return out, http.StatusOK, nil
}

// read retries a read-only/preview call like the MCP journey's call helper.
func (b *installedBrowser) read(ctx context.Context, name string, input any, data any) {
	b.t.Helper()
	var failure error
	for attempt := 1; attempt <= 4; attempt++ {
		reply, _, err := b.operation(ctx, name, input, "")
		if err == nil && reply.Status == "ok" {
			if err = installedJourneyDecode(reply.Data, data); err != nil {
				b.t.Fatal("browser response data", name, err)
			}
			return
		}
		failure = err
		if failure == nil {
			failure = fmt.Errorf("status %s request %s", reply.Status, reply.RequestID)
		}
		b.t.Logf("browser %s attempt %d: %v", name, attempt, failure)
		if attempt < 4 && installedJourneyPause(ctx, 2*time.Second) != nil {
			break
		}
	}
	b.t.Fatalf("browser %s: %v", name, failure)
}

// installedBrowserComparable decodes data and recursively removes the named
// per-call identity/time keys, keeping every other field for comparison.
func installedBrowserComparable(raw json.RawMessage, volatile ...string) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, errors.New("comparable data is not an object")
	}
	drop := map[string]bool{}
	for _, k := range volatile {
		drop[k] = true
	}
	var strip func(any)
	strip = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if drop[k] {
					delete(x, k)
					continue
				}
				strip(child)
			}
		case []any:
			for _, child := range x {
				strip(child)
			}
		}
	}
	strip(value)
	return value, nil
}

// installedBrowserSame compares two stripped objects and names (only) the
// differing top-level fields; required fields must be present in both.
func installedBrowserSame(what string, mcp, browser map[string]any, required ...string) error {
	for _, k := range required {
		if _, ok := mcp[k]; !ok {
			return fmt.Errorf("%s: MCP reply lacks %s", what, k)
		}
		if _, ok := browser[k]; !ok {
			return fmt.Errorf("%s: browser reply lacks %s", what, k)
		}
	}
	keys := map[string]bool{}
	for k := range mcp {
		keys[k] = true
	}
	for k := range browser {
		keys[k] = true
	}
	var differ []string
	for k := range keys {
		if !reflect.DeepEqual(mcp[k], browser[k]) {
			differ = append(differ, k)
		}
	}
	if len(differ) > 0 {
		sort.Strings(differ)
		return fmt.Errorf("%s: browser and MCP differ in %s", what, strings.Join(differ, ", "))
	}
	return nil
}

// Per-call identities and clocks. Execution and plan digests bind the
// preview's own capture ID and deadline, so they differ for two previews of
// the same normalized plan; asOf is the read time of a handling notice.
var installedBrowserPreviewVolatile = []string{"preview_id", "expires_at", "execution_digest", "assessmentID", "planDigest", "generatedAt", "validUntil"}

// qualifyInstalledBrowserJourney is the S-02 browser half after the MCP
// capture is published and downloaded: as the same Keycloak user through the
// console cookie session it (a) previews the same pod-status capture and
// compares the normalized scope, selected Pod, impact/unknowns, blockers and
// warnings, data exposure and retention/deletion with a fresh MCP preview;
// (b) opens the published case and the approved pod-status extract and
// compares them with MCP get_case and the MCP approved excerpt; (c) prepares
// and fetches the native download through the console route and requires its
// SHA-256 to equal the MCP-downloaded bytes.
//
// mcp is the journey's validated MCP call (readReply). The approved query adds
// one principal query (Records allow three) and one shared acquisition worker,
// which projectionCheck waits out before the native session, as in the MCP
// path. The native session is a third download session on the workload's
// allocation: it needs nativeCapacityProfile Records >= 4 (3 sessions of
// 8 KiB/16 MiB exceed the 24 KiB/36 MiB three-record allocation).
func qualifyInstalledBrowserJourney(t *testing.T, ctx context.Context, identity *installedIdentity, publicRoot *x509.Certificate, address, origin string,
	mcp func(context.Context, string, any) (installedJourneyEnvelope, error), previewArguments map[string]any,
	caseID, artifactID string, approved query.ContextExcerpt, native []byte, projectionCheck installedProjectionCheck, diagnose func()) {
	t.Helper()
	if identity == nil || mcp == nil || projectionCheck == nil || caseID == "" || artifactID == "" || len(native) == 0 {
		t.Fatal("browser journey requires the MCP journey's published case, approved excerpt and native bytes")
	}
	b := identity.consoleSession(t, ctx, publicRoot, address, origin)
	mcpRead := func(name string, args any) json.RawMessage {
		t.Helper()
		var failure error
		for attempt := 1; attempt <= 4; attempt++ {
			reply, err := mcp(ctx, name, args)
			if err == nil && reply.Status == "ok" {
				return reply.Data
			}
			failure = err
			if failure == nil {
				failure = fmt.Errorf("status %s request %s", reply.Status, reply.RequestID)
			}
			if attempt < 4 && installedJourneyPause(ctx, 2*time.Second) != nil {
				break
			}
		}
		diagnose()
		t.Fatalf("browser journey MCP %s: %v", name, failure)
		return nil
	}

	// (a) Preview parity: the same input through both transports, back to back.
	mcpPreview := mcpRead("preview_capture", previewArguments)
	var browserPreview json.RawMessage
	b.read(ctx, "preview_capture", previewArguments, &browserPreview)
	left, e1 := installedBrowserComparable(mcpPreview, installedBrowserPreviewVolatile...)
	right, e2 := installedBrowserComparable(browserPreview, installedBrowserPreviewVolatile...)
	if e1 != nil || e2 != nil {
		t.Fatal("browser journey preview data", e1, e2)
	}
	if err := installedBrowserSame("preview", left, right, "target_ref", "preset_ref", "selected_pods", "pod_selection", "pod_count", "max_bytes",
		"capture_enabled", "approval_required", "blockers", "warnings", "lifecycle_plan", "capture_assessment"); err != nil {
		diagnose()
		t.Fatal(err)
	}
	var pinned struct {
		CaptureEnabled bool `json:"capture_enabled"`
		SelectedPods   []struct {
			UID string `json:"uid"`
		} `json:"selected_pods"`
	}
	if json.Unmarshal(browserPreview, &pinned) != nil || !pinned.CaptureEnabled || len(pinned.SelectedPods) != 1 || pinned.SelectedPods[0].UID == "" {
		t.Fatal("browser preview did not pin the regional Pod")
	}
	t.Log("installed browser journey: console and MCP previews agree on scope, selected Pod, impact/unknowns, blockers/warnings, data exposure and retention/deletion")

	// (b) Case and approved extract parity.
	caseArgs := map[string]string{"case_id": caseID}
	var browserCase json.RawMessage
	b.read(ctx, "get_case", caseArgs, &browserCase)
	left, e1 = installedBrowserComparable(mcpRead("get_case", caseArgs), "asOf")
	right, e2 = installedBrowserComparable(browserCase, "asOf")
	if e1 != nil || e2 != nil {
		t.Fatal("browser journey case data", e1, e2)
	}
	if err := installedBrowserSame("case", left, right, "case", "artifacts"); err != nil {
		diagnose()
		t.Fatal(err)
	}
	var opened struct {
		Artifacts []struct {
			ArtifactID string    `json:"artifact_id"`
			ExpiresAt  time.Time `json:"expires_at"`
		} `json:"artifacts"`
	}
	if json.Unmarshal(browserCase, &opened) != nil || len(opened.Artifacts) != 1 || opened.Artifacts[0].ArtifactID != artifactID || !time.Now().Before(opened.Artifacts[0].ExpiresAt) {
		t.Fatal("browser case does not offer the original current artifact")
	}
	expires := opened.Artifacts[0].ExpiresAt
	verify := projectionCheck(artifactID)
	excerpt, handle, operation := installedBrowserExcerpt(t, ctx, b, caseID, artifactID, expires, diagnose)
	if !reflect.DeepEqual(excerpt, approved) {
		t.Fatal("browser approved extract differs from the MCP approved extract")
	}
	if err := installedProjectionMatchesNative(excerpt, native); err != nil {
		t.Fatal(err)
	}
	retired := verify(handle, operation)
	if retired == nil {
		t.Fatal("browser approved query lacks its exact worker retirement check")
	}
	t.Log("installed browser journey: console case and approved pod-status extract equal the MCP replies")

	// (c) Native download through the console route, bound to this session.
	prepare := map[string]string{"artifact_id": artifactID, "idempotency_key": "installed-browser-download"}
	prepareOnce := func() installedJourneyDownload {
		t.Helper()
		// An uncertain prepare is never replayed; only an acknowledged
		// continue_preparation permits the same-key call again.
		reply, status, err := b.operation(ctx, "prepare_artifact_download", prepare, prepare["idempotency_key"])
		var d installedJourneyDownload
		if err != nil || reply.Status != "ok" || installedJourneyDecode(reply.Data, &d) != nil {
			diagnose()
			t.Fatal("browser download preparation", status, reply.Status, reply.RequestID, err)
		}
		return d
	}
	download := prepareOnce()
	original, until := download.DownloadID, download.ExpiresAt
	if original == "" || until.IsZero() || until.After(expires) {
		t.Fatal("browser download deadline", until)
	}
	limit, stop := context.WithDeadline(ctx, installedJourneyEarlier(until, time.Now().Add(5*time.Minute)))
	defer stop()
	for download.State == "Preparing" {
		if installedJourneyPause(limit, 2*time.Second) != nil {
			diagnose()
			t.Fatal("browser download stayed Preparing")
		}
		if download.ContinuePreparation {
			download = prepareOnce()
		} else {
			b.read(limit, "get_artifact_download", map[string]string{"download_id": original}, &download)
		}
		if download.DownloadID != original || !download.ExpiresAt.Equal(until) {
			t.Fatal("browser download changed its original identity/deadline")
		}
	}
	if download.State != "Ready" || download.ContentPath != "/api/v1/downloads/"+original+"/content" || download.SizeBytes == nil || download.SHA256 == "" {
		diagnose()
		t.Fatal("browser download was not prepared", download.State)
	}
	retired()
	// An <a href download> navigation: cookie only, no Origin/CSRF/bearer.
	get, err := http.NewRequestWithContext(ctx, http.MethodGet, b.base+download.ContentPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	get.Header.Set("Sec-Fetch-Site", "same-origin")
	get.Header.Set("Sec-Fetch-Mode", "navigate")
	get.Header.Set("Sec-Fetch-Dest", "document")
	response, err := b.client.Do(get)
	if err != nil {
		diagnose()
		t.Fatal("browser download content", err)
	}
	bytesRead, err := io.ReadAll(io.LimitReader(response.Body, artifact.MaxContextBytes+1))
	response.Body.Close()
	got, want := sha256.Sum256(bytesRead), sha256.Sum256(native)
	if err != nil || response.StatusCode != http.StatusOK || int64(len(bytesRead)) != *download.SizeBytes || hex.EncodeToString(got[:]) != download.SHA256 || got != want {
		diagnose()
		t.Fatal("browser native download differs from its metadata or the MCP-downloaded bytes", response.StatusCode, len(bytesRead), err)
	}
	t.Logf("installed browser journey: the console session downloaded the native pod-status file (%d bytes, SHA-256 equal to the MCP download)", len(bytesRead))

	// (d) ADR-232 console sharing, browser focus only (its binding adds
	// evidence-owner): the console session, with evidence:share as a default
	// scope of the console client, shares the exact artifact version, lists
	// it as its own and revokes it. Recipient reads run in the MCP share
	// focus; recipient IDs are not looked up.
	if installedJourneyFocus() != "browser" {
		return
	}
	var digest struct {
		Artifacts []struct {
			Digest string `json:"digest"`
		} `json:"artifacts"`
	}
	if json.Unmarshal(browserCase, &digest) != nil || len(digest.Artifacts) != 1 || digest.Artifacts[0].Digest == "" {
		t.Fatal("browser case lacks the verified artifact version")
	}
	share := map[string]any{"case_id": caseID, "artifacts": []map[string]string{{"artifactID": artifactID, "digest": digest.Artifacts[0].Digest}},
		"recipients":   []map[string]string{{"kind": "User", "issuer": identity.Issuer, "id": "installed-browser-recipient"}},
		"data_classes": []string{"metadata"}, "operations": []string{"get_case"}, "expires_at": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
		"reason": "installed browser share", "idempotency_key": "installed-browser-share"}
	var created struct {
		ShareID string `json:"share_id"`
		Phase   string `json:"phase"`
	}
	reply, status, err := b.operation(ctx, "create_share", share, "installed-browser-share")
	if err != nil || reply.Status != "ok" || installedJourneyDecode(reply.Data, &created) != nil || created.ShareID == "" || created.Phase != "Active" {
		diagnose()
		t.Fatal("browser create_share", status, reply.Status, reply.RequestID, err)
	}
	type ownedShares struct {
		Shares []struct {
			ShareID string `json:"share_id"`
			CaseID  string `json:"case_id"`
			Phase   string `json:"phase"`
		} `json:"shares"`
	}
	phase := func() string {
		t.Helper()
		var mine ownedShares
		b.read(ctx, "list_shares", map[string]any{"view": "owned", "limit": 100}, &mine)
		for _, s := range mine.Shares {
			if s.ShareID == created.ShareID && s.CaseID == caseID {
				return s.Phase
			}
		}
		return ""
	}
	if got := phase(); got != "Active" {
		t.Fatal("browser owned shares lack the new share", got)
	}
	reply, status, err = b.operation(ctx, "revoke_share", map[string]any{"share_id": created.ShareID, "expected_revision": 1, "idempotency_key": "installed-browser-revoke"}, "installed-browser-revoke")
	if err != nil || reply.Status != "ok" {
		diagnose()
		t.Fatal("browser revoke_share", status, reply.Status, reply.RequestID, err)
	}
	if got := phase(); got != "Revoked" {
		t.Fatal("browser owned share was not revoked", got)
	}
	t.Logf("installed browser journey: the console session created, listed and revoked share %s", created.ShareID)
}

// installedBrowserExcerpt runs the console's approved inspection: one
// get_file_excerpt, then at most four same-handle get_query_result polls on
// the fixed schedule. Paid polls are not retried on transport failure.
func installedBrowserExcerpt(t *testing.T, ctx context.Context, b *installedBrowser, caseID, artifactID string, expires time.Time, diagnose func()) (query.ContextExcerpt, string, string) {
	t.Helper()
	once := func(name string, input any) installedJourneyEnvelope {
		t.Helper()
		reply, status, err := b.operation(ctx, name, input, "")
		if err != nil {
			diagnose()
			t.Fatal("browser approved operation outcome unavailable; no replay", name, status, err)
		}
		return reply
	}
	result := once("get_file_excerpt", map[string]any{"case_id": caseID, "artifact_id": artifactID, "line_start": 1, "max_lines": 14})
	operation, handle := result.RequestID, ""
	var first, until time.Time
	for poll := 0; result.Status == "pending"; poll++ {
		var pending struct {
			Handle   string    `json:"query_handle"`
			Retry    int       `json:"retry_after_seconds"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
		}
		if installedJourneyDecode(result.Data, &pending) != nil || pending.Handle == "" || pending.Retry < 1 || pending.Observed.IsZero() || pending.Expires.IsZero() || pending.Expires.After(expires) {
			t.Fatal("invalid pending browser approved query")
		}
		if poll == 0 {
			handle, first, until = pending.Handle, pending.Observed, pending.Expires
		}
		if pending.Handle != handle || !pending.Expires.Equal(until) || poll >= 4 {
			t.Fatal("browser approved query changed identity/lifetime or exhausted its poll allowance")
		}
		next, err := installedProjectionPollTime(first, until, time.Now(), time.Duration(pending.Retry)*time.Second, poll)
		if err != nil {
			t.Fatal(err)
		}
		if installedJourneyPause(ctx, time.Until(next)) != nil {
			t.Fatal("browser approved poll canceled", ctx.Err())
		}
		result = once("get_query_result", map[string]string{"query_handle": handle})
	}
	if result.Status != "ok" {
		diagnose()
		t.Fatal("browser approved query did not return content", result.Status)
	}
	var excerpt query.ContextExcerpt
	if handle != "" {
		var resolved struct {
			Handle string                   `json:"query_handle"`
			Tool   string                   `json:"tool_name"`
			Result installedJourneyEnvelope `json:"result"`
		}
		if installedJourneyDecode(result.Data, &resolved) != nil || resolved.Handle != handle || resolved.Tool != "get_file_excerpt" || resolved.Result.Status != "ok" || installedJourneyDecode(resolved.Result.Data, &excerpt) != nil {
			t.Fatal("browser approved result changed original handle/tool")
		}
	} else if installedJourneyDecode(result.Data, &excerpt) != nil {
		t.Fatal("immediate browser approved result")
	}
	return excerpt, handle, operation
}

// qualifyInstalledBrowserSubmission is the optional browser-submitted request:
// a console preview, request_capture under its own idempotency key and the
// same resolve/continue recovery as MCP, then the passive wait until the
// capture is collected and its case publishes one artifact. It consumes one
// more capture record, resolution-lane records and a full collection and
// publication (up to five minutes). Call it before the MCP capture so it does
// not shorten the MCP artifact's 600-second window; it downloads nothing.
func qualifyInstalledBrowserSubmission(t *testing.T, ctx context.Context, identity *installedIdentity, publicRoot *x509.Certificate, address, origin string, previewArguments map[string]any, diagnose func()) (captureID, caseID string) {
	t.Helper()
	b := identity.consoleSession(t, ctx, publicRoot, address, origin)
	var accepted installedJourneyAcceptedReceipt
	for attempt := 1; ; attempt++ {
		accepted = installedJourneyAcceptedReceipt{}
		var preview struct {
			PreviewID      string `json:"preview_id"`
			CaptureEnabled bool   `json:"capture_enabled"`
		}
		b.read(ctx, "preview_capture", previewArguments, &preview)
		if !preview.CaptureEnabled || preview.PreviewID == "" {
			t.Fatal("browser preview does not permit capture")
		}
		key := fmt.Sprintf("installed-browser-capture-%d", attempt)
		request := map[string]any{"preview_id": preview.PreviewID, "idempotency_key": key}
		submit := func(input map[string]any) string {
			t.Helper()
			reply, status, err := b.operation(ctx, "request_capture", input, key)
			if err != nil {
				if status >= 400 && status < 500 && status != http.StatusTooManyRequests {
					diagnose()
					t.Fatal("browser request_capture refused before dispatch", status)
				}
				t.Logf("browser request_capture transport/HTTP %d: %v", status, err)
				return "OutcomeUnknown"
			}
			if reply.Status != "ok" {
				var failure struct {
					Code string `json:"code"`
				}
				if json.Unmarshal(reply.Data, &failure) != nil || failure.Code == "" {
					t.Fatal("browser request_capture failure without code")
				}
				return failure.Code
			}
			var current struct {
				CaptureID string `json:"capture_id"`
			}
			if installedJourneyDecode(reply.Data, &current) != nil || accepted.remember(current.CaptureID, time.Now()) != nil {
				t.Fatal("browser request_capture accepted identity")
			}
			return ""
		}
		resolve := func() (installedJourneyDisposition, error) {
			reply, _, err := b.operation(ctx, "resolve_capture_request", request, key)
			if err != nil {
				return installedJourneyDisposition{}, err
			}
			if reply.Status != "ok" {
				return installedJourneyDisposition{}, errors.New("original browser capture request remains unresolved")
			}
			var d installedJourneyDisposition
			err = installedJourneyDecode(reply.Data, &d)
			if err == nil && d.State == "accepted" {
				err = accepted.remember(d.CaptureID, time.Now())
			}
			return d, err
		}
		closed, err := installedJourneyRecoverCapture(ctx, submit(request), resolve, func() (string, string) {
			return submit(map[string]any{"preview_id": preview.PreviewID, "idempotency_key": key, "continue_acquisition": true}), accepted.CaptureID
		}, func() error {
			d, err := resolve()
			if err != nil {
				return err
			}
			if accepted.CaptureID == "" || d.State != "accepted" || d.CaptureID != accepted.CaptureID {
				return errors.New("browser request was not accepted once")
			}
			return nil
		}, installedJourneyPause, func(id string) (installedJourneyCaptureProgress, error) {
			var p installedJourneyCaptureProgress
			reply, _, err := b.operation(ctx, "get_capture", map[string]string{"capture_id": id}, "")
			if err != nil {
				return p, err
			}
			if reply.Status != "ok" {
				return p, errors.New("original accepted browser capture progress is unavailable")
			}
			return p, installedJourneyDecode(reply.Data, &p)
		})
		if err != nil {
			diagnose()
			t.Fatal("browser capture request was not accepted", err)
		}
		if !closed {
			break
		}
		if attempt == 3 {
			diagnose()
			t.Fatal("browser capture requests closed without admission after three reviews")
		}
		if installedJourneyPause(ctx, 2*time.Second) != nil {
			t.Fatal("browser capture request", ctx.Err())
		}
	}
	if accepted.CaptureID == "" {
		t.Fatal("browser capture lost its acknowledged receipt")
	}
	limit, stop := context.WithTimeout(ctx, 5*time.Minute)
	defer stop()
	var progress installedJourneyCaptureProgress
	for {
		reply, _, err := b.operation(limit, "get_capture", map[string]string{"capture_id": accepted.CaptureID}, "")
		if err == nil && reply.Status == "ok" {
			if installedJourneyDecode(reply.Data, &progress) != nil {
				t.Fatal("browser capture progress data")
			}
			ready, err := installedJourneyCaptureCaseReady(limit, accepted.CaptureID, progress)
			if err != nil {
				diagnose()
				t.Fatal("browser capture was not collected", err)
			}
			if ready {
				break
			}
		}
		if installedJourneyPause(limit, 2*time.Second) != nil {
			diagnose()
			t.Fatal("browser capture did not publish a case in time")
		}
	}
	for {
		var published struct {
			Artifacts []struct {
				ArtifactID string `json:"artifact_id"`
			} `json:"artifacts"`
		}
		reply, _, err := b.operation(limit, "get_case", map[string]string{"case_id": progress.CaseID}, "")
		if err == nil && reply.Status == "ok" && installedJourneyDecode(reply.Data, &published) == nil && len(published.Artifacts) > 0 {
			if len(published.Artifacts) != 1 || published.Artifacts[0].ArtifactID == "" {
				t.Fatal("browser case lists more than its one pod-status artifact")
			}
			break
		}
		if installedJourneyPause(limit, 2*time.Second) != nil {
			diagnose()
			t.Fatal("browser case did not publish its artifact in time")
		}
	}
	t.Log("installed browser journey: the console session submitted, resolved and saw publication of its own pod-status capture")
	return accepted.CaptureID, progress.CaseID
}
