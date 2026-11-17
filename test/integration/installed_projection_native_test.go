package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func installedApprovedScopes(scope string) bool {
	scopes := strings.Fields(scope)
	return slices.Contains(scopes, "evidence:read") && !slices.Contains(scopes, "evidence:download") && !slices.Contains(scopes, "evidence:capture")
}

type installedProjectionCheck func(artifactID string) func(queryID, operationID string) func()

// This adds at most six audited normal operations: one scoped denial, one
// get_extract fileExcerpt and four already-budgeted result polls. Existing normal128 /
// resolution8 fixture allocations are unchanged; no unknown call is replayed.
func installedApprovedProjection(t *testing.T, ctx context.Context, identity *installedIdentity, transport http.RoundTripper, origin, caseID, artifactID, pod string, expires time.Time, check installedProjectionCheck) (query.ContextExcerpt, func()) {
	t.Helper()
	if check == nil {
		t.Fatal("approved projection requires independent SQL readback")
	}
	verify := check(artifactID)
	source := identity.approvedTokenSource(origin)
	if _, err := source.Token(ctx); err != nil {
		t.Fatal("real approved-only OAuth session", err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-approved-journey", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, source.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal("approved-only MCP session", err)
	}
	defer session.Close()
	call := func(name string, args any) installedJourneyEnvelope {
		t.Helper()
		result, e := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if e != nil {
			t.Fatal("approved operation outcome unavailable; no replay", name, e)
		}
		var out installedJourneyEnvelope
		raw, e := json.Marshal(result.StructuredContent)
		if e != nil || wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil || result.IsError != (out.Status == "error") {
			t.Fatal("approved operation response contract", name)
		}
		return out
	}
	denied := call("prepare_artifact_download", map[string]string{"artifact_id": artifactID, "idempotency_key": "approved-only-download-denied"})
	if denied.Status != "error" {
		t.Fatal("read-only OAuth session obtained download preparation")
	}
	verify("", "")
	result := call("get_extract", map[string]any{"view": "fileExcerpt", "case_id": caseID, "artifact_id": artifactID, "line_start": 1, "limit": 14})
	originalOperation := result.RequestID
	originalHandle := ""
	var until time.Time
	for poll := 0; result.Status == "pending"; poll++ {
		var pending struct {
			Handle   string    `json:"query_handle"`
			Revision int       `json:"revision"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
		}
		if installedJourneyDecode(result.Data, &pending) != nil || pending.Handle == "" || pending.Revision < 1 || pending.Observed.IsZero() || pending.Expires.IsZero() || pending.Expires.After(expires) {
			t.Fatal("invalid pending approved query")
		}
		if poll == 0 {
			originalHandle, until = pending.Handle, pending.Expires
		}
		if pending.Handle != originalHandle || !pending.Expires.Equal(until) || poll >= 4 {
			t.Fatal("approved query changed identity/lifetime or exhausted original poll allowance")
		}
		result = call("get_query_result", map[string]any{"query_handle": originalHandle, "after_revision": pending.Revision})
	}
	if result.Status != "ok" {
		t.Fatal("approved query did not return content", result.Status)
	}
	var excerpt query.ContextExcerpt
	if originalHandle != "" {
		var resolved struct {
			Handle string                   `json:"query_handle"`
			Tool   string                   `json:"tool_name"`
			Result installedJourneyEnvelope `json:"result"`
		}
		if installedJourneyDecode(result.Data, &resolved) != nil || resolved.Handle != originalHandle || resolved.Tool != "get_extract" || resolved.Result.Status != "ok" || installedJourneyDecode(resolved.Result.Data, &excerpt) != nil {
			t.Fatal("approved result changed original handle/tool")
		}
	} else if installedJourneyDecode(result.Data, &excerpt) != nil {
		t.Fatal("immediate approved result")
	}
	quoted, _ := json.Marshal(pod)
	if excerpt.LogicalPath != query.ContextLogicalPath || excerpt.LineStart != 1 || len(excerpt.Lines) != 14 || excerpt.Lines[2] != "podUID: "+string(quoted) {
		t.Fatal("approved result is not the exact selected Pod's fixed projection")
	}
	retired := verify(originalHandle, originalOperation)
	if retired == nil {
		t.Fatal("approved query lacks its exact worker retirement check")
	}
	t.Log("installed journey: real read-only OAuth scope received approved pod-status content through shared acquisition; native-download scope was absent and preparation refused")
	return excerpt, retired
}

func installedProjectionMatchesNative(excerpt query.ContextExcerpt, native []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(native, &fields) != nil {
		return errors.New("invalid native context")
	}
	names := []string{"format", "namespaceUID", "podUID", "resourceVersion", "observedAt", "phase", "ready", "initialized", "scheduled", "runtimeInstances", "running", "waiting", "terminated", "restarts"}
	if len(fields) != len(names) {
		return errors.New("native context field set changed")
	}
	expected := make([]string, 0, len(names))
	for _, name := range names {
		raw, ok := fields[name]
		if !ok {
			return errors.New("native context lacks fixed field")
		}
		var decoded any
		if json.Unmarshal(raw, &decoded) != nil {
			return errors.New("native context field invalid")
		}
		if name == "observedAt" {
			var observed time.Time
			if json.Unmarshal(raw, &observed) != nil {
				return errors.New("native observation invalid")
			}
			decoded = observed.UTC().Format(time.RFC3339Nano)
		}
		encoded, err := json.Marshal(decoded)
		if err != nil {
			return err
		}
		expected = append(expected, fmt.Sprintf("%s: %s", name, encoded))
	}
	if excerpt.LogicalPath != query.ContextLogicalPath || excerpt.LineStart != 1 || !reflect.DeepEqual(excerpt.Lines, expected) {
		return errors.New("approved content differs from the exact native evidence")
	}
	return nil
}
