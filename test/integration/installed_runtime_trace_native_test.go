package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/transport/presentation"
	"github.com/google/pprof/profile"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const manualRuntimeTraceName = "go-runtime-trace"

func installedRuntimeTraceVariant() bool {
	// Reuse the closed selector's validation even when this is not a trace.
	installedHeapProfileVariant()
	return os.Getenv("ASSERVAT_PROFILE_VARIANT") == "trace"
}

func manualRuntimeTraceArguments(cluster, namespace, workload string) map[string]any {
	args := manualHeapProfileArguments(cluster, namespace, workload)
	c := args["profile_composition"].(map[string]any)
	c["components"] = []any{map[string]any{"id": "trace", "profileRef": map[string]string{"catalog": "namespace", "name": manualRuntimeTraceName, "version": "v1"}}}
	c["maxTotalBytes"], c["maxDuration"] = 32<<20, "20s"
	return args
}
func manualRuntimeTraceDefinition() (map[string]any, error) {
	d, err := manualHeapProfileDefinition()
	if err != nil {
		return nil, err
	}
	d["displayName"], d["description"] = "Go runtime trace", "Finite Go scheduler and execution trace."
	r := d["recipe"].(map[string]any)
	r["description"], r["maxDuration"], r["maxTotalBytes"] = d["description"], "20s", 32<<20
	a := r["actions"].([]any)[0].(map[string]any)
	a["id"] = "trace"
	p := a["parameters"].(map[string]any)
	p["type"], p["mode"], p["duration"], p["forceGC"] = "runtimeTrace", "interval", "5s", false
	l := a["limits"].(map[string]any)
	l["maxBytes"], l["timeout"] = 32<<20, "10s"
	d["editableFields"] = []any{map[string]any{"actionID": "trace", "field": "actionMaxBytes", "label": "Output limit"}}
	return d, nil
}
func qualifyRuntimeTraceCase(t *testing.T, target presentation.ContextCaseTargetData, facts *presentation.ProfileAcquisitionData, cluster, namespace, workload, podUID, podName string) {
	t.Helper()
	if target.ClusterID != cluster || target.Namespace != namespace || target.WorkloadName != workload || target.PodUID != podUID || (target.PodName != "" && target.PodName != podName) || facts == nil || facts.RequestedType != "runtimeTrace" || facts.Mode != "interval" || facts.RequestedDurationMillis == nil || *facts.RequestedDurationMillis != 5000 || facts.ForceGC || facts.StartedAt == nil || facts.CompletedAt == nil || facts.CompletedAt.Before(*facts.StartedAt) || facts.ClockUncertaintyMillis != nil || facts.ProcessAttribution != "unknown" {
		body, _ := json.Marshal(facts)
		t.Fatalf("trace case lost original target or verified acquisition facts: target=%+v profile=%s", target, body)
	}
}

// This ordinary read-only client cannot turn a native trace into a pprof query.
func qualifyRuntimeTraceSummaryDenied(t *testing.T, ctx context.Context, identity *installedIdentity, transport http.RoundTripper, origin, caseID, artifactID string) {
	t.Helper()
	source := identity.approvedTokenSource(origin)
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-trace-read-only", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, source.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_profile_summary", Arguments: map[string]any{"case_id": caseID, "artifact_id": artifactID, "sample_type": "cpu", "top_n": 20}})
	if err != nil {
		t.Fatal("trace summary refusal unavailable; no replay", err)
	}
	raw, err := json.Marshal(result.StructuredContent)
	var reply installedJourneyEnvelope
	var refusal struct {
		Code string `json:"code"`
	}
	if err != nil || wire.ValidateOutput("get_profile_summary", raw) != nil || json.Unmarshal(raw, &reply) != nil || !result.IsError || reply.Status != "error" || json.Unmarshal(reply.Data, &refusal) != nil || refusal.Code != "NotAvailable" {
		t.Fatal("trace was accepted by pprof summary or returned an unexpected refusal", string(raw))
	}
	t.Log("runtime trace: ordinary read-only pprof summary refused before query allocation; no query worker or analyzer used")
}

func installedRuntimeTraceNoQueries(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string) func(string, string) {
	return func(captureID, artifactID string) {
		t.Helper()
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		var clean bool
		err := admin.QueryRow(call, `SELECT EXISTS(SELECT 1 FROM context_catalog WHERE root_id=$1 AND capture_id=$2 AND artifact_id=$3)
 AND NOT EXISTS(SELECT 1 FROM context_query WHERE root_id=$1)
 AND NOT EXISTS(SELECT 1 FROM context_query_worker w JOIN context_query q ON q.id=w.query_id WHERE q.root_id=$1)
 AND EXISTS(SELECT 1 FROM context_query_backing WHERE root_id=$1 AND allocated=0)`, root, captureID, artifactID).Scan(&clean)
		if err != nil || !clean {
			t.Fatal("trace native-only journey unexpectedly allocated query capacity or lost pinned catalog source", err)
		}
	}
}

func validateManualRuntimeTrace(ctx context.Context, native []byte, path string) ([]byte, error) {
	if err := diagnostics.CheckGoTrace(bytes.NewReader(native)); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, native, 0600); err != nil {
		return nil, err
	}
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := installedOutput(call, installedLocalToolTimeout, "go", "tool", "trace", "-pprof=sched", path)
	if err != nil {
		return nil, err
	}
	p, err := profile.ParseData(out)
	if err != nil {
		return nil, err
	}
	if err = p.CheckValid(); err != nil {
		return nil, err
	}
	return out, nil
}
func qualifyManualRuntimeTraceNative(t *testing.T, ctx context.Context, native []byte, captureID string) {
	t.Helper()
	out, err := validateManualRuntimeTrace(ctx, native, "../results/manual-runtime-trace.trace")
	if err != nil {
		t.Fatal("authenticated runtime trace did not open with finite local go tool trace", err)
	}
	if err := os.WriteFile("../results/manual-runtime-trace-sched.pb.gz", out, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime trace %s: %d authenticated native bytes; go tool trace emitted valid scheduler pprof without browser or symbol lookup; no CPU/heap summary, busy or Stop branch", captureID, len(native))
}
