package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// installedJourneyHistory is the ADR-236 part of the share focus
// (ASSERVAT_JOURNEY_FOCUS=share), after the short journey published one
// capture: the developer lists the workload's recent captures over MCP and
// finds that capture; the journey's unrelated principal (no workload rights,
// like a share-only recipient) is refused; the developer reads its settings,
// collects again through preview_capture history_capture_id, which runs the
// ordinary preview, submits it with request_capture and waits until the new
// capture is collected and leads the history. Every authority input is the
// installed product's own.
func installedJourneyHistory(t *testing.T, ctx context.Context, wire *contracts.InvestigationContracts, owner *installedIdentity, transport http.RoundTripper, origin string, target map[string]string, captureID string, diagnose func()) {
	t.Helper()
	connect := func(name string, token func(context.Context) (string, error)) *sdk.ClientSession {
		t.Helper()
		client := sdk.NewClient(&sdk.Implementation{Name: name, Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
		session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
		if err != nil {
			t.Fatal("installed history MCP session", name, err)
		}
		return session
	}
	developer := connect("installed-history-developer", owner.mcpTokenSource(origin).Token)
	defer developer.Close()
	outsiderTokens := owner.unrelated().mcpTokenSource(origin)
	outsider := connect("installed-history-outsider", outsiderTokens.Token)
	defer outsider.Close()
	// try reports a transport error; call fails the test on it.
	try := func(session *sdk.ClientSession, name string, arguments any, data any) (string, string, error) {
		t.Helper()
		result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: arguments})
		if err != nil {
			t.Logf("installed history: %s -> transport %v", name, err)
			return "", "", err
		}
		reply, code, err := installedJourneyReplyCode(wire, name, result)
		if err != nil {
			diagnose()
			t.Fatal("installed history response contract", name, err)
		}
		if code == "" && data != nil {
			if err := installedJourneyDecode(reply.Data, data); err != nil {
				t.Fatal("installed history data", name, err)
			}
		}
		t.Logf("installed history: %s -> %s %s request %s", name, reply.Status, code, reply.RequestID)
		return reply.Status, code, nil
	}
	call := func(session *sdk.ClientSession, name string, arguments any, data any) (string, string) {
		t.Helper()
		status, code, err := try(session, name, arguments, data)
		if err != nil {
			diagnose()
			t.Fatal("installed history call", name, err)
		}
		return status, code
	}
	type page struct {
		History []struct {
			CaptureID     string `json:"capture_id"`
			Origin        string `json:"origin"`
			Phase         string `json:"phase"`
			EvidenceState string `json:"evidence_state"`
			RepeatState   string `json:"repeat_state"`
		} `json:"history"`
	}
	list := map[string]any{"target_ref": target}
	// 1. The developer's own capture is in the workload's history.
	var before page
	// (The share focus's capture-time-share capture, ADR-235, may be newer.)
	listed := -1
	status, code := call(developer, "list_capture_history", list, &before)
	for i, e := range before.History {
		if e.CaptureID == captureID && e.Origin == "manual" && e.Phase == "Succeeded" && e.RepeatState == "available" {
			listed = i
		}
	}
	if status != "ok" || listed < 0 {
		diagnose()
		t.Fatal("installed history list", status, code, before)
	}
	// 2. A principal without workload rights sees no history and no settings.
	if status, code := call(outsider, "list_capture_history", list, nil); status != "error" || code != "NotAvailable" {
		t.Fatal("installed unrelated principal listed history", status, code)
	}
	if status, code := call(outsider, "get_capture_settings", map[string]string{"capture_id": captureID}, nil); status != "error" || code != "NotAvailable" {
		t.Fatal("installed unrelated principal read settings", status, code)
	}
	if status, code := call(outsider, "preview_capture", map[string]string{"history_capture_id": captureID}, nil); status != "error" || code != "NotAvailable" {
		t.Fatal("installed unrelated principal repeated a capture", status, code)
	}
	// 3. Settings name the original target and requested retention.
	var settings struct {
		CaptureID string `json:"capture_id"`
		Settings  struct {
			Target struct {
				Namespace string `json:"namespace"`
				Workload  struct {
					Kind string `json:"kind"`
					Name string `json:"name"`
				} `json:"workloadRef"`
			} `json:"target"`
			RequestedRetention string `json:"requested_retention"`
		} `json:"settings"`
	}
	if status, code := call(developer, "get_capture_settings", map[string]string{"capture_id": captureID}, &settings); status != "ok" || settings.CaptureID != captureID || settings.Settings.Target.Namespace != target["namespace"] || settings.Settings.Target.Workload.Name != target["name"] || settings.Settings.RequestedRetention == "" {
		t.Fatal("installed capture settings", status, code, settings)
	}
	// 4. Collect again: the ordinary preview of the same target, then submit.
	var preview struct {
		PreviewID    string `json:"preview_id"`
		Repeated     string `json:"repeated_from_capture_id"`
		Enabled      bool   `json:"capture_enabled"`
		SelectedPods []struct {
			UID string `json:"uid"`
		} `json:"selected_pods"`
	}
	// A preview is retryable NotAvailable while a fact it gathers expires
	// before the others are read ("facts/current"), e.g. while the workload's
	// storage binding is refreshed after the capture-time-share capture just
	// used it. Like the journey's own preview, retry up to four reviews.
	var accepted struct {
		CaptureID string
	}
	var err error
	accepted.CaptureID, err = installedJourneyReviewAndSubmit(ctx, func(name string, arguments any, data any) (string, string) {
		// A lost request reply is an unknown outcome, resolved like the journey's.
		if name == "request_capture" {
			if status, code, err := try(developer, name, arguments, data); err == nil {
				return status, code
			}
			return "error", "OutcomeUnknown"
		}
		return call(developer, name, arguments, data)
	}, func(attempt int) (map[string]any, error) {
		preview.PreviewID, preview.Repeated, preview.Enabled, preview.SelectedPods = "", "", false, nil
		status, code, err := installedJourneyRetryUnavailable(ctx, func() (string, string, error) {
			return try(developer, "preview_capture", map[string]string{"history_capture_id": captureID}, &preview)
		})
		if err != nil || status != "ok" || preview.PreviewID == "" || preview.Repeated != captureID || !preview.Enabled || len(preview.SelectedPods) != 1 {
			diagnose()
			t.Fatal("installed repeat preview", status, code, err, preview)
		}
		return map[string]any{"preview_id": preview.PreviewID, "idempotency_key": fmt.Sprintf("installed-history-repeat-%d", attempt)}, nil
	})
	if err != nil {
		diagnose()
		t.Fatal("installed repeat request", err)
	}
	if accepted.CaptureID == "" || accepted.CaptureID == captureID {
		t.Fatal("installed repeat did not create a new capture", accepted.CaptureID)
	}
	// 5. The repeat is collected like any capture and leads the history.
	deadline := time.Now().Add(4 * time.Minute)
	for {
		var progress struct {
			Phase string `json:"phase"`
		}
		status, _ := call(developer, "get_capture", map[string]string{"capture_id": accepted.CaptureID}, &progress)
		if status == "ok" && progress.Phase == "Succeeded" {
			break
		}
		if status == "ok" && (progress.Phase == "Failed" || progress.Phase == "Indeterminate") || time.Now().After(deadline) {
			diagnose()
			t.Fatal("installed repeated capture was not collected", status, progress.Phase)
		}
		if installedJourneyPause(ctx, 2*time.Second) != nil {
			t.Fatal("installed repeated capture", ctx.Err())
		}
	}
	var after page
	if status, _, err := installedJourneyRetryUnavailable(ctx, func() (string, string, error) { return try(developer, "list_capture_history", list, &after) }); err != nil || status != "ok" || len(after.History) != len(before.History)+1 || after.History[0].CaptureID != accepted.CaptureID || after.History[listed+1].CaptureID != captureID {
		t.Fatal("installed history after repeat", after)
	}
	t.Logf("installed history: listed capture %s, refused the unrelated principal, collected again as capture %s", captureID, accepted.CaptureID)
}
