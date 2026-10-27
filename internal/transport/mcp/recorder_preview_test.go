package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/presentation"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpRecorderFixture compiles the real recorder plan; facts are synthetic.
type mcpRecorderFixture struct{ mcpCaptureFixture }

func (f *mcpRecorderFixture) PreviewComposition(_ context.Context, _ identities.CurrentIdentity, in value.ContextIntent) (app.RecorderPreviewResult, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	target := targets.PodResolution{Request: targets.Request{ClusterID: in.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: in.Target.Namespace, UID: "ns"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: in.Target.Namespace, NamespaceUID: "ns", Name: "api-a", UID: "pod", NodeName: "worker", ControllerUID: "rs"}, NodeUID: "node", NodeBootID: "00000000-0000-4000-8000-000000000006", PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	evidence, err := compiler.RecorderEvidenceType(*in.Composition)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	r, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "set", Generation: 1, Digest: [32]byte{7}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: evidence, AnchorAt: now}, now)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	plan, err := compiler.CompileRecorder(planning.RecorderInput{CaptureID: "00000000-0000-4000-8000-000000000045", Executor: testIdentity().Principal, Target: target, Composition: *in.Composition, Retention: r, Deadline: now.Add(time.Minute)}, nil, now)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	a, err := compiler.AssessRecorder(plan, "00000000-0000-4000-8000-000000000161", now)
	if err != nil {
		return app.RecorderPreviewResult{}, err
	}
	p := value.ContextPreview{ID: "00000000-0000-4000-8000-000000000020", Intent: in, Deadline: now.Add(5 * time.Minute), ScopeDigest: plan.ScopeDigest, Target: target.Request}
	return app.RecorderPreviewResult{Preview: p, Plan: plan, Assessment: a, ValidUntil: f.deadline()}, nil
}

// Browser and MCP share presentation.Call; this exercises the MCP SDK's own
// input/output schema handling of the composition branch (SC-CPR-005 parity).
func TestCompositionPreviewThroughMCP(t *testing.T) {
	var handler *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	f := &mcpRecorderFixture{}
	ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, CollectionEnabled: true, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f, f)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
		i := testIdentity()
		i.Scopes = append(i.Scopes, "evidence:capture")
		return i, nil
	}), ops)
	if err != nil {
		t.Fatal(err)
	}
	arguments := map[string]any{}
	if err := json.Unmarshal([]byte(`{"target_ref":{"cluster_id":"00000000-0000-4000-8000-000000000001","namespace":"payments","kind":"Deployment","name":"api"},"profile_composition":{"components":[{"id":"calls","profileRef":{"catalog":"builtin","name":"syscall-activity","version":"v1"},"overrides":[{"actionID":"syscalls","field":"actionExecutionMode","value":"onTrigger"},{"actionID":"syscalls","field":"syscallBefore","value":"0s"},{"actionID":"syscalls","field":"syscallFilter","value":{"mode":"include","names":["openat","connect"]}}]}],"maxTotalBytes":16777216,"maxDuration":"30s"}}`), &arguments); err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "recorder-test-agent", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
	hc := *server.Client()
	hc.Transport = bearerTransport{hc.Transport}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + Path, HTTPClient: &hc, MaxRetries: -1, DisableStandaloneSSE: true}, &sdk.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	called, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "preview_capture", Arguments: arguments})
	if err != nil || called.IsError || called.StructuredContent == nil {
		t.Fatalf("composition preview over MCP: %v %#v", err, called)
	}
	b, _ := json.Marshal(called.StructuredContent)
	if !strings.Contains(string(b), `"RecorderUnavailable"`) || !strings.Contains(string(b), `"data_class":"extract"`) || !strings.Contains(string(b), `"executionMode":"onTrigger"`) || !strings.Contains(string(b), `"requestedBefore":"0s"`) {
		t.Fatalf("structured result: %s", b)
	}
}
