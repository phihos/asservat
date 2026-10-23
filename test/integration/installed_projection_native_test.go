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
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func installedApprovedScopes(scope string) bool {
	scopes := strings.Fields(scope)
	return slices.Contains(scopes, "evidence:read") && !slices.Contains(scopes, "evidence:download") && !slices.Contains(scopes, "evidence:capture")
}

type installedProjectionCheck func(artifactID string) func(queryID, operationID string)

// Operator-only readback proves that the approved path did not create a dummy
// native session, used one original query worker and consumed actual key slots.
// It supplies no runtime input, grants or product authority.
func installedProjectionSQLCheck(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string) installedProjectionCheck {
	return func(artifact string) func(string, string) {
		t.Helper()
		countDownloads := func() int {
			t.Helper()
			var n int
			if err := admin.QueryRow(ctx, "SELECT count(*) FROM artifact_download WHERE root_id=$1 AND artifact_id=$2", root, artifact).Scan(&n); err != nil {
				t.Fatal("approved-only download count", err)
			}
			return n
		}
		before := countDownloads()
		return func(handle, operation string) {
			t.Helper()
			if countDownloads() != before {
				t.Fatal("read-only approved workflow created a native download session")
			}
			if operation == "" {
				return
			} // acknowledged scoped denial, before query admission
			limit, stop := context.WithTimeout(ctx, 10*time.Second)
			defer stop()
			for limit.Err() == nil {
				var id, worker string
				var polls, batches, workers, keys, closed int
				var active, uncertain bool
				err := admin.QueryRow(limit, `SELECT q.id::text,q.worker_id::text,q.polls,q.generation,q.active_batch IS NOT NULL,q.uncertain,
     (SELECT count(*) FROM download_worker w WHERE w.query_id=q.id AND w.session_id IS NULL AND w.id=q.worker_id AND w.binding_json IS NOT NULL),
     (SELECT count(*) FROM context_query_key_binding k WHERE k.query_id=q.id AND k.used_roles=7),
     (SELECT count(*) FROM context_query_batch b WHERE b.query_id=q.id AND b.closed AND b.native_closed)
     FROM context_query q WHERE q.root_id=$1 AND q.operation_id=$2 AND q.query->'Scope'->>'ArtifactID'=$3`, root, operation, artifact).Scan(&id, &worker, &polls, &batches, &active, &uncertain, &workers, &keys, &closed)
				if err == nil && (handle == "" || id == handle) && worker != "" && workers == 1 && polls <= 4 && batches >= 1 && batches <= 2 && keys == batches && closed == batches && !active && !uncertain {
					t.Logf("installed approved query: one exact shared worker, %d paid poll(s), %d joined batch(es), three consumed key roles per batch; no native session", polls, batches)
					return
				}
				if installedJourneyPause(limit, 100*time.Millisecond) != nil {
					break
				}
			}
			t.Fatal("approved response lacked exact joined SQL worker/key/batch readback")
		}
	}
}

// This adds at most six audited normal operations: one scoped denial, one
// get_file_excerpt and four already-budgeted result polls. Existing normal64 /
// resolution2 fixture allocations are unchanged; no unknown call is replayed.
func installedApprovedProjection(t *testing.T, ctx context.Context, identity *installedIdentity, transport http.RoundTripper, origin, caseID, artifactID, pod string, expires time.Time, check installedProjectionCheck) query.ContextExcerpt {
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
	result := call("get_file_excerpt", map[string]any{"case_id": caseID, "artifact_id": artifactID, "line_start": 1, "max_lines": 14})
	originalOperation := result.RequestID
	originalHandle := ""
	var firstObserved, until time.Time
	for poll := 0; result.Status == "pending"; poll++ {
		var pending struct {
			Handle   string    `json:"query_handle"`
			Retry    int       `json:"retry_after_seconds"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
		}
		if installedJourneyDecode(result.Data, &pending) != nil || pending.Handle == "" || pending.Retry < 1 || pending.Observed.IsZero() || pending.Expires.IsZero() || pending.Expires.After(expires) {
			t.Fatal("invalid pending approved query")
		}
		if poll == 0 {
			originalHandle, firstObserved, until = pending.Handle, pending.Observed, pending.Expires
		}
		if pending.Handle != originalHandle || !pending.Expires.Equal(until) || poll >= 4 {
			t.Fatal("approved query changed identity/lifetime or exhausted original poll allowance")
		}
		next, err := installedProjectionPollTime(firstObserved, until, time.Now(), time.Duration(pending.Retry)*time.Second, poll)
		if err != nil {
			t.Fatal(err)
		}
		if installedJourneyPause(ctx, time.Until(next)) != nil {
			t.Fatal("approved poll canceled", ctx.Err())
		}
		result = call("get_query_result", map[string]string{"query_handle": originalHandle})
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
		if installedJourneyDecode(result.Data, &resolved) != nil || resolved.Handle != originalHandle || resolved.Tool != "get_file_excerpt" || resolved.Result.Status != "ok" || installedJourneyDecode(resolved.Result.Data, &excerpt) != nil {
			t.Fatal("approved result changed original handle/tool")
		}
	} else if installedJourneyDecode(result.Data, &excerpt) != nil {
		t.Fatal("immediate approved result")
	}
	quoted, _ := json.Marshal(pod)
	if excerpt.LogicalPath != query.ContextLogicalPath || excerpt.LineStart != 1 || len(excerpt.Lines) != 14 || excerpt.Lines[2] != "podUID: "+string(quoted) {
		t.Fatal("approved result is not the exact selected Pod's fixed projection")
	}
	verify(originalHandle, originalOperation)
	t.Log("installed journey: real read-only OAuth scope received approved pod-status content through shared acquisition; native-download scope was absent and preparation refused")
	return excerpt
}

// Spread the original four paid polls across the fixed query lifetime instead
// of spending them immediately while a cold Pod starts. Server not-before wins;
// an expired or incompatible schedule refuses, never renews the query.
func installedProjectionPollTime(start, until, now time.Time, retry time.Duration, poll int) (time.Time, error) {
	if start.IsZero() || !start.Before(until) || now.Before(start) || !now.Before(until) || retry <= 0 || poll < 0 || poll >= 4 {
		return time.Time{}, errors.New("invalid approved query poll bound")
	}
	next := start.Add(until.Sub(start) * time.Duration(poll+1) / 5)
	if floor := now.Add(retry); floor.After(next) {
		next = floor
	}
	if !next.Before(until) {
		return time.Time{}, errors.New("approved poll cannot fit original query lifetime")
	}
	return next, nil
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
