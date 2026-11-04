package integration

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
)

// Validate the actual public request and synthetic endpoint answer through the
// planner before spending an installed run. This grants no runtime authority.
func TestInstalledManualProfileRequestCompiles(t *testing.T) {
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "")
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	const cluster = "00000000-0000-4000-8000-000000000001"
	for name, input := range map[string]map[string]any{"complete": approvedRecordingArguments(cluster, "payments", "api"), "stop": manualProfileStopArguments(cluster, "payments", "api")} {
		t.Run(name, func(t *testing.T) { checkManualProfilePlan(t, cluster, input) })
	}
}

func checkManualProfilePlan(t *testing.T, cluster string, input map[string]any, resolved ...planvalue.CatalogProfile) planvalue.RecorderPlan {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateInput("preview_capture", raw); err != nil {
		t.Fatal("manual profile request is not a public capture input", err)
	}
	compositionJSON, _ := json.Marshal(input["profile_composition"])
	var public contracts.CaptureComposition
	if err := json.Unmarshal(compositionJSON, &public); err != nil {
		t.Fatal(err)
	}
	composition, err := conversion.CompositionFromWire(public)
	if err != nil {
		t.Fatal("profile composition conversion", err)
	}
	composition.Resolved = resolved
	now := time.Now().UTC().Truncate(time.Microsecond)
	target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: cluster, Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "namespace", Name: "api-a", UID: "pod", ControllerUID: "replicaset"}, PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "policies", Generation: 1, Digest: artifact.Digest{1}}, Complete: true, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "profile", RequestedSeconds: 600, AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	in := planvalue.RecorderInput{CaptureID: cluster, Executor: identity.Principal{Issuer: "https://identity.example.test", Subject: "requester", ClientID: "console", Kind: identity.Human}, Target: target, Composition: *composition, Retention: retention, Deadline: now.Add(time.Minute), NodeRecorder: true, RequireApproval: true}
	_, err = compiler.CompileRecorder(in, recordingCompiler{}, now)
	var needed compiler.EndpointResolutionNeeded
	if !errors.As(err, &needed) {
		t.Fatal("profile endpoint request compiled without a region resolution", err)
	}
	if !kube.ProfileEndpointsValid(manualProfileEndpoints()) {
		t.Fatal("invalid installed endpoint template")
	}
	in.Endpoints = []targets.ProfileEndpointResolution{{Request: needed.Request, SourceKind: targets.ProfileEndpointTemplateBinding, SourceName: needed.Request.Bindings[0].TemplateRef, AddressMode: "targetLoopback", Port: 6060, DeclaredPortName: "diagnostics", PathPolicy: "go-pprof/v1", DefinitionDigest: artifact.Digest{1}, EndpointDigest: artifact.Digest{2}, ResolvedAt: now}}
	plan, err := compiler.CompileRecorder(in, nil, now)
	if err != nil {
		t.Fatal("public profile request cannot compile through the actual planner", err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != "profile" {
		t.Fatal("profile plan did not select exactly one profile action", plan.Actions)
	}
	if _, err := compiler.ProfileContextFromScope(*composition, target.Request, plan.CanonicalScope); err != nil {
		t.Fatal("profile plan cannot enter accepted context execution", err)
	}
	return plan
}

func TestInstalledManualProfileFundsOneConservativeSummary(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	if got := nativeCapacityProfile(); got.Records < 10 || got.Records >= 20 {
		t.Fatal("manual fixture must fund one ten-unit summary, not two", got.Records)
	}
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "approved-recording")
	if got := nativeCapacityProfile(); got.Records != 8 {
		t.Fatal("unrelated fixture capacity changed", got.Records)
	}
}

func TestInstalledManualProfileStopRequestsUseSeparateWireContracts(t *testing.T) {
	var preview installedApprovedRecordingPreview
	if err := json.Unmarshal([]byte(`{"preview_id":"00000000-0000-4000-8000-000000000001","lifecycle_plan":{"actions":[{"actionID":"cpu.cpu"}]}}`), &preview); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	original, resolution := manualProfileStopRequests(preview, now)
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]any{"request_capture": original, "resolve_capture_request": resolution} {
		raw, _ := json.Marshal(input)
		if err := wire.ValidateInput(name, raw); err != nil {
			t.Fatal(name, err)
		}
	}
	raw, _ := json.Marshal(original["result_access"])
	var access struct {
		ActionIDs                             []string `json:"actionIds"`
		Operations                            []string `json:"operations"`
		ClientIDs                             []string `json:"clientIDs"`
		MaxArtifacts, MaxBytes, MaxOperations int64
		NotAfter                              time.Time
	}
	if json.Unmarshal(raw, &access) != nil || len(access.ActionIDs) != 1 || access.ActionIDs[0] != "cpu.cpu" || len(access.Operations) != 1 || access.Operations[0] != "download_artifact" || len(access.ClientIDs) != 1 || access.ClientIDs[0] != "mcp" || access.MaxArtifacts != 1 || access.MaxBytes != 64<<20 || access.MaxOperations != 100 || !access.NotAfter.Equal(now.Add(time.Hour)) {
		t.Fatal("Stop raw approval lacks its fixed result-access instruction", string(raw))
	}
	if len(resolution) != 2 || resolution["preview_id"] != original["preview_id"] || resolution["idempotency_key"] != original["idempotency_key"] {
		t.Fatal("resolution is not the original passive identity")
	}
}
