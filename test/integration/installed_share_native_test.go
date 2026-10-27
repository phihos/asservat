package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// installedJourneyShare is the ADR-232 share focus (ASSERVAT_JOURNEY_FOCUS=share)
// after the short journey published one pod-status artifact: the journey's
// unrelated principal is refused get_case; the developer, holding
// evidence-owner through the installed AccessBinding and the evidence:share
// scope, shares the artifact with that principal over MCP; the recipient then
// reads the case (access "shared"), lists the share and (ADR-233) prepares
// and Range-downloads the native file; after the developer revokes the share,
// get_case, download preparation and the content route are refused. Finally
// (ADR-235) the developer requests one new capture shared with the recipient
// in the same request; after publication get_capture reports Shared and the
// recipient reads the new case. Every authority input is the installed
// product's own.
func installedJourneyShare(t *testing.T, ctx context.Context, wire *contracts.InvestigationContracts, owner *installedIdentity, transport http.RoundTripper, origin, caseID, artifactID string, native []byte, previewArguments map[string]any, diagnose func()) {
	t.Helper()
	connect := func(name string, token func(context.Context) (string, error)) *sdk.ClientSession {
		t.Helper()
		client := sdk.NewClient(&sdk.Implementation{Name: name, Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
		session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
		if err != nil {
			t.Fatal("installed share MCP session", name, err)
		}
		return session
	}
	outsiderTokens := owner.unrelated().mcpTokenSource(origin)
	if _, err := outsiderTokens.Token(ctx); err != nil || outsiderTokens.subject == "" {
		t.Fatal("installed recipient token", err)
	}
	recipient := connect("installed-share-recipient", outsiderTokens.Token)
	defer recipient.Close()
	developer := connect("installed-share-owner", owner.shareTokenSource(origin).Token)
	defer developer.Close()
	// call returns the validated envelope's status, error code and data.
	// try reports a transport error; call fails the test on it.
	try := func(session *sdk.ClientSession, name string, arguments any, data any) (string, string, error) {
		t.Helper()
		result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: arguments})
		if err != nil {
			t.Logf("installed share: %s -> transport %v", name, err)
			return "", "", err
		}
		reply, code, err := installedJourneyReplyCode(wire, name, result)
		if err != nil {
			diagnose()
			t.Fatal("installed share response contract", name, err)
		}
		if code == "" && data != nil {
			if err := installedJourneyDecode(reply.Data, data); err != nil {
				t.Fatal("installed share data", name, err)
			}
		}
		t.Logf("installed share: %s -> %s %s request %s", name, reply.Status, code, reply.RequestID)
		return reply.Status, code, nil
	}
	call := func(session *sdk.ClientSession, name string, arguments any, data any) (string, string) {
		t.Helper()
		status, code, err := try(session, name, arguments, data)
		if err != nil {
			diagnose()
			t.Fatal("installed share call", name, err)
		}
		return status, code
	}
	type caseView struct {
		Case struct {
			Access string `json:"access"`
		} `json:"case"`
		Artifacts []struct {
			ArtifactID string `json:"artifact_id"`
			Digest     string `json:"digest"`
		} `json:"artifacts"`
	}
	getCase := func(session *sdk.ClientSession) (caseView, bool) {
		var v caseView
		status, _ := call(session, "get_case", map[string]string{"case_id": caseID}, &v)
		return v, status == "ok"
	}
	// 1. Before the share: the unrelated principal is refused.
	if _, ok := getCase(recipient); ok {
		t.Fatal("installed unrelated principal read the case before any share")
	}
	// 2. The developer (evidence-owner) shares the exact artifact version.
	owned, ok := getCase(developer)
	if !ok || owned.Case.Access != "ordinary" || len(owned.Artifacts) != 1 || owned.Artifacts[0].ArtifactID != artifactID {
		t.Fatal("installed owner case", owned)
	}
	var created struct {
		ShareID string `json:"share_id"`
		Phase   string `json:"phase"`
	}
	share := map[string]any{"case_id": caseID, "artifacts": []map[string]string{{"artifactID": artifactID, "digest": owned.Artifacts[0].Digest}},
		"recipients":   []map[string]string{{"kind": "User", "issuer": owner.Issuer, "id": outsiderTokens.subject}},
		"data_classes": []string{"metadata"}, "operations": []string{"get_case"}, "expires_at": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
		"reason": "installed share focus", "idempotency_key": "installed-share-1"}
	if status, code := call(developer, "create_share", share, &created); status != "ok" || created.ShareID == "" || created.Phase != "Active" {
		diagnose()
		t.Fatal("installed create_share", status, code)
	}
	// 3. The recipient reads the shared artifact, and only it.
	shared, ok := getCase(recipient)
	if !ok || shared.Case.Access != "shared" || len(shared.Artifacts) != 1 || shared.Artifacts[0].ArtifactID != artifactID || shared.Artifacts[0].Digest != owned.Artifacts[0].Digest {
		diagnose()
		t.Fatal("installed recipient could not read the shared case", shared)
	}
	var received struct {
		Shares []struct {
			ShareID string `json:"share_id"`
			CaseID  string `json:"case_id"`
			Phase   string `json:"phase"`
		} `json:"shares"`
	}
	if status, _ := call(recipient, "list_shares", map[string]string{"view": "received"}, &received); status != "ok" || len(received.Shares) != 1 || received.Shares[0].ShareID != created.ShareID || received.Shares[0].Phase != "Active" {
		t.Fatal("installed received shares", received)
	}
	// ADR-233: the recipient prepares the native download through the share and
	// fetches a byte range with its own download-route token.
	prepare := map[string]string{"artifact_id": artifactID, "idempotency_key": "installed-share-download"}
	var download installedJourneyDownload
	if status, code := call(recipient, "prepare_artifact_download", prepare, &download); status != "ok" || download.DownloadID == "" {
		diagnose()
		t.Fatal("installed recipient could not prepare the shared download", status, code)
	}
	for deadline := time.Now().Add(3 * time.Minute); download.State == "Preparing"; {
		if time.Now().After(deadline) {
			diagnose()
			t.Fatal("installed recipient download was not prepared in time")
		}
		time.Sleep(time.Second)
		name, args := "get_artifact_download", map[string]string{"download_id": download.DownloadID}
		if download.ContinuePreparation {
			name, args = "prepare_artifact_download", prepare
		}
		if status, code := call(recipient, name, args, &download); status != "ok" {
			diagnose()
			t.Fatal("installed recipient download poll", name, code)
		}
	}
	if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil || *download.SizeBytes != int64(len(native)) || len(native) < 2 {
		diagnose()
		t.Fatal("installed recipient download", download.State, download.ContentPath)
	}
	contentURL, contentClient := strings.TrimSuffix(origin, "/")+download.ContentPath, &http.Client{Transport: transport, Timeout: 2 * time.Minute}
	recipientDownloads := owner.unrelated()
	half := int64(len(native)) / 2
	head, _, err := installedJourneyPartial(installedJourneyContent(t, ctx, contentClient, contentURL, recipientDownloads.downloadToken(), map[string]string{"Range": "bytes=0-" + strconv.FormatInt(half-1, 10)}), 0, half, int64(len(native)))
	if err != nil || !bytes.Equal(head, native[:half]) {
		diagnose()
		t.Fatal("installed recipient range download", err)
	}
	// ADR-238 (migration 00091 applied by the installer): the recipient cannot
	// transfer management, and the owner cannot name a team they do not hold.
	team := map[string]any{"mode": "teams", "teams": []map[string]string{{"kind": "Group", "issuer": owner.Issuer, "id": "installed-not-an-owner-team"}}}
	if status, code := call(recipient, "transfer_share", map[string]any{"share_id": created.ShareID, "expected_revision": 1, "idempotency_key": "installed-share-transfer", "management": team}, nil); status != "error" || code != "NotAvailable" {
		t.Fatal("installed recipient transferred share management", status, code)
	}
	foreign := maps.Clone(share)
	foreign["idempotency_key"], foreign["management"] = "installed-share-foreign-team", team
	if status, code := call(developer, "create_share", foreign, nil); status != "error" || code != "ManagementNotHeld" {
		t.Fatal("installed share named a team the owner does not hold", status, code)
	}
	// The management-only administrator listing is refused to a recipient.
	if status, code := call(recipient, "list_shares", map[string]any{"view": "administration", "limit": 10}, nil); status != "error" || code != "NotAvailable" {
		t.Fatal("installed recipient listed every share", status, code)
	}
	// 4. Revocation ends the recipient's read at its next request.
	var revoked struct {
		Phase    string `json:"phase"`
		Revision int64  `json:"revision"`
	}
	if status, code := call(developer, "revoke_share", map[string]any{"share_id": created.ShareID, "expected_revision": 1, "idempotency_key": "installed-share-revoke"}, &revoked); status != "ok" || revoked.Phase != "Revoked" || revoked.Revision != 2 {
		t.Fatal("installed revoke_share", status, code)
	}
	if _, ok := getCase(recipient); ok {
		t.Fatal("installed recipient read the case after revocation")
	}
	// The next download request re-reads the share: preparation and the
	// remaining range of the existing session are refused.
	if status, _ := call(recipient, "prepare_artifact_download", map[string]string{"artifact_id": artifactID, "idempotency_key": "installed-share-download-2"}, nil); status != "error" {
		t.Fatal("installed recipient prepared a download after revocation")
	}
	rest := installedJourneyContent(t, ctx, contentClient, contentURL, recipientDownloads.downloadToken(), map[string]string{"Range": "bytes=" + strconv.FormatInt(half, 10) + "-"})
	body, _ := io.ReadAll(io.LimitReader(rest.Body, int64(len(native))+1))
	rest.Body.Close()
	if rest.StatusCode == http.StatusOK || rest.StatusCode == http.StatusPartialContent || bytes.Contains(body, native[half:]) {
		t.Fatal("installed recipient downloaded content after revocation", rest.StatusCode)
	}
	var mine struct {
		Shares []struct {
			ShareID string `json:"share_id"`
			Phase   string `json:"phase"`
		} `json:"shares"`
	}
	if status, _ := call(developer, "list_shares", map[string]string{"view": "owned"}, &mine); status != "ok" || len(mine.Shares) != 1 || mine.Shares[0].Phase != "Revoked" {
		t.Fatal("installed owned shares", mine)
	}
	t.Logf("installed share: unrelated principal refused, shared get_case read, recipient range download (%d of %d bytes), revocation refused the next read, prepare and range (share %s, content status after revocation %d)", half, len(native), created.ShareID, rest.StatusCode)

	// 5. ADR-235: a one-step capture shared with the recipient at request time.
	arguments := map[string]any{"sharing": map[string]any{"recipients": []map[string]string{{"kind": "User", "issuer": owner.Issuer, "id": outsiderTokens.subject}}}}
	for k, v := range previewArguments {
		arguments[k] = v
	}
	var previewed struct {
		PreviewID string   `json:"preview_id"`
		Warnings  []string `json:"warnings"`
	}
	var accepted struct {
		CaptureID string `json:"capture_id"`
	}
	accepted.CaptureID, err = installedJourneyReviewAndSubmit(ctx, func(name string, arguments any, data any) (string, string) {
		return call(developer, name, arguments, data)
	}, func(attempt int) (map[string]any, error) {
		previewed.PreviewID, previewed.Warnings = "", nil
		if status, code, err := installedJourneyRetryUnavailable(ctx, func() (string, string, error) { return try(developer, "preview_capture", arguments, &previewed) }); err != nil || status != "ok" || previewed.PreviewID == "" || len(previewed.Warnings) != 1 {
			diagnose()
			t.Fatal("installed sharing preview", status, code, err, previewed)
		}
		return map[string]any{"preview_id": previewed.PreviewID, "idempotency_key": fmt.Sprintf("installed-capture-share-%d", attempt)}, nil
	})
	if err != nil {
		diagnose()
		t.Fatal("installed sharing request_capture", err)
	}
	var progress struct {
		Phase   string `json:"phase"`
		CaseID  string `json:"case_id"`
		Sharing *struct {
			State   string `json:"state"`
			ShareID string `json:"share_id"`
		} `json:"sharing"`
	}
	for deadline := time.Now().Add(4 * time.Minute); ; {
		if status, _ := call(developer, "get_capture", map[string]string{"capture_id": accepted.CaptureID}, &progress); status == "ok" && progress.Sharing != nil {
			if progress.Phase == "Succeeded" && progress.CaseID != "" && progress.Sharing.State == "Shared" {
				break
			}
			if progress.Sharing.State == "SharingUnavailable" || progress.Phase == "Failed" || progress.Phase == "Indeterminate" {
				diagnose()
				t.Fatal("installed capture-time share not materialized", progress.Phase, progress.Sharing.State)
			}
		}
		if time.Now().After(deadline) {
			diagnose()
			t.Fatal("installed capture-time share did not publish in time", progress.Phase)
		}
		time.Sleep(2 * time.Second)
	}
	var sharedCase caseView
	if status, _ := call(recipient, "get_case", map[string]string{"case_id": progress.CaseID}, &sharedCase); status != "ok" || sharedCase.Case.Access != "shared" || len(sharedCase.Artifacts) != 1 {
		diagnose()
		t.Fatal("installed recipient could not read the capture-time share", sharedCase)
	}
	t.Logf("installed share: capture %s shared at request time (share %s); the recipient read case %s", accepted.CaptureID, progress.Sharing.ShareID, progress.CaseID)
}
