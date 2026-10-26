package integration

import (
	"context"
	"net/http"
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
// reads the case (access "shared") and lists the share, but native download
// preparation stays refused; after the developer revokes the share, get_case
// is refused again. Every authority input is the installed product's own.
func installedJourneyShare(t *testing.T, ctx context.Context, wire *contracts.InvestigationContracts, owner *installedIdentity, transport http.RoundTripper, origin, caseID, artifactID string, diagnose func()) {
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
	call := func(session *sdk.ClientSession, name string, arguments any, data any) (string, string) {
		t.Helper()
		result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: arguments})
		if err != nil {
			diagnose()
			t.Fatal("installed share call", name, err)
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
		return reply.Status, code
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
	// Native download is increment 3: the share grants only get_case.
	if status, _ := call(recipient, "prepare_artifact_download", map[string]string{"artifact_id": artifactID, "idempotency_key": "installed-share-download"}, nil); status != "error" {
		t.Fatal("installed recipient prepared a native download through a share")
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
	var mine struct {
		Shares []struct {
			ShareID string `json:"share_id"`
			Phase   string `json:"phase"`
		} `json:"shares"`
	}
	if status, _ := call(developer, "list_shares", map[string]string{"view": "owned"}, &mine); status != "ok" || len(mine.Shares) != 1 || mine.Shares[0].Phase != "Revoked" {
		t.Fatal("installed owned shares", mine)
	}
	t.Logf("installed share: unrelated principal refused, shared get_case read, download refused, revocation refused the next read (share %s)", created.ShareID)
}
