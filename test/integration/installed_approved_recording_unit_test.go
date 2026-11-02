package integration

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/presentation"
)

// Invalid request wiring should fail before spending an installed collector run.
// Contract validation grants no capture authority and runs no collector.
func TestInstalledApprovedRecordingPublicInput(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	input := approvedRecordingArguments("00000000-0000-4000-8000-000000000001", "payments", "api")
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateInput("preview_capture", raw); err != nil {
		t.Fatal("actual approved recording preview input", err)
	}
}

// Both the harness and bootstrap consumer must agree on the owned fixture:
// one hub plus one workload cluster for this fast focus. The real service
// assertion stays strict; this test catches shape drift without starting Kind.
func TestInstalledApprovedRecordingFixtureShape(t *testing.T) {
	for _, tc := range []struct {
		focus    string
		clusters int
		fast     bool
	}{
		{"approved-recording", 2, true}, {"manual-syscall", 2, true}, {"manual-mixed", 2, true}, {"manual-raw", 2, true}, {"policy-recording", 2, true}, {"ongoing-save", 2, true}, {"ongoing-incident", 2, true}, {"ongoing-syscall", 2, true}, {"ongoing-mixed", 2, true}, {"native-paced", 2, true}, {"journey", 2, true}, {"browser", 2, true},
		{"policy", 2, true}, {"alert", 2, true}, {"logresource", 2, true},
		{"restart", 2, true}, {"upgrade", 2, true}, {"share", 2, true},
		{"chain", 2, false}, {"clusters", 3, true}, {"", 3, false}, {"unknown", 3, false},
	} {
		t.Run(tc.focus, func(t *testing.T) {
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", tc.focus)
			if got := installedClusterCount(); got != tc.clusters {
				t.Fatalf("owned fixture clusters=%d; want %d", got, tc.clusters)
			}
			if got := installedFastFixture(); got != tc.fast {
				t.Fatalf("fast feature fixture=%v; want %v", got, tc.fast)
			}
			wantRecording := tc.focus == "approved-recording" || tc.focus == "manual-syscall" || tc.focus == "manual-mixed" || tc.focus == "manual-raw" || tc.focus == "native-paced" || tc.focus == "policy-recording" || tc.focus == "ongoing-save" || tc.focus == "ongoing-incident" || tc.focus == "ongoing-syscall" || tc.focus == "ongoing-mixed"
			if got := installedRecordingFocus(); got != wantRecording {
				t.Fatalf("recording focus parent-return guard=%v; want %v", got, wantRecording)
			}
			if (tc.focus == "approved-recording" || tc.focus == "native-paced") && (installedRegionalInstallerChecks(1) || !installedRegionalInstallerChecks(2)) {
				t.Fatal("approved focus changed regional feature/chain coverage")
			}
		})
	}
}

// The collector stage must never apply the chart's installation-intent
// ConfigMap into an invented release namespace or mutate connector staging.
// This checks the exact runtime command builder without requiring Helm/Kind.
func TestInstalledApprovedRecordingCollectorRenderStage(t *testing.T) {
	for _, namespace := range []string{"asservat-connector", "connector-selected-by-the-installer"} {
		args := approvedRecordingCollectorRenderArgs(namespace, "operator-values.json")
		value := func(flag string) string {
			for i := range args {
				if args[i] == flag && i+1 < len(args) {
					return args[i+1]
				}
			}
			return ""
		}
		if value("--show-only") != "templates/collector.yaml" {
			t.Fatal("collector stage includes unrelated foundation resources")
		}
		if value("--namespace") != namespace {
			t.Fatal("render namespace does not match the actual regional installation")
		}
		if value("-f") != "operator-values.json" {
			t.Fatal("render lost its exact installed endpoint/image values")
		}
	}
}

func TestInstalledApprovedRecordingRejectsPlanOnlyBeforeApproval(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, blockers string
		want           bool
	}{
		{"approval-only", `[{"code":"ApprovalRequired"}]`, true},
		{"plan-only", `[{"code":"ApprovalRequired"},{"code":"RecorderUnavailable"}]`, false},
		{"collection-disabled", `[{"code":"ApprovalRequired"},{"code":"CollectionDisabled"}]`, false},
		{"missing-blocker", `[]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"preview_id":"00000000-0000-4000-8000-000000000001","expires_at":"` + now.Add(time.Minute).Format(time.RFC3339Nano) + `","approval_required":true,"capture_enabled":false,"selected_pods":[{"uid":"exact-pod","name":"api-a"}],"blockers":` + tc.blockers + `}`
			var p installedApprovedRecordingPreview
			if json.Unmarshal([]byte(raw), &p) != nil || p.readyForApproval(now) != tc.want {
				t.Fatal("unrecordable preview passed the initial approval guard", tc.name)
			}
		})
	}
}

func TestInstalledApprovedRecordingRetriesOnlyTypedTransientReads(t *testing.T) {
	for _, tc := range []struct {
		code        string
		retry, want bool
	}{
		{"NotAvailable", true, true}, {"NotAvailable", false, false}, {"RecorderUnavailable", false, false}, {"ReviewChanged", false, false}, {"CapacityUnavailable", true, false}, {"ApprovalRequired", false, false},
	} {
		t.Run(tc.code+fmt.Sprint(tc.retry), func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"code": tc.code, "retryable": tc.retry})
			reply := installedJourneyEnvelope{Status: "error", Data: raw}
			if installedApprovedRecordingCanRetry(reply, tc.code) != tc.want {
				t.Fatal("unexpected read retry", tc.code)
			}
		})
	}
}

// ADR-279 manual-raw focus: the public request is valid, and the published
// namespace definition compiles through the actual planner (synthetic facts,
// test filter compiler; no capture) into an acceptable raw recording with
// raw approval, observation limits and the reviewed caps.
func TestInstalledManualRawRequestCompiles(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-raw")
	const cluster = "00000000-0000-4000-8000-000000000001"
	input := approvedRecordingArguments(cluster, "payments", "api")
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateInput("preview_capture", raw); err != nil {
		t.Fatal("manual raw request is not a public capture input", err)
	}
	definition, err := manualRawProfileDefinition()
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(map[string]any{"name": manualRawProfileName, "version": manualRawProfileVersion, "definition": definition})
	if err != nil {
		t.Fatal(err)
	}
	compositionJSON, _ := json.Marshal(input["profile_composition"])
	var public presentation.CompositionInput
	if err := json.Unmarshal(compositionJSON, &public); err != nil {
		t.Fatal(err)
	}
	ref := planvalue.ProfileRef{Catalog: "namespace", Name: manualRawProfileName, Version: manualRawProfileVersion}
	resolved := planvalue.ProfileComposition{MaxTotalBytes: public.MaxTotalBytes, MaxDuration: public.MaxDuration,
		Resolved: []planvalue.CatalogProfile{{Ref: ref, SourceClusterID: cluster, SourceNamespaceUID: "namespace", SourceUID: "raw-capture-uid", Document: document, Enabled: true}}}
	for _, c := range public.Components {
		component := planvalue.ProfileComponent{ID: c.ID, Profile: planvalue.ProfileRef{Catalog: c.ProfileRef.Catalog, Name: c.ProfileRef.Name, Version: c.ProfileRef.Version}}
		for _, o := range c.Overrides {
			edit := planvalue.ProfileEdit{ActionID: o.ActionID, Field: o.Field}
			if err := json.Unmarshal(o.Value, &edit.Text); err != nil {
				t.Fatal("raw override", o.Field, err)
			}
			component.Edits = append(component.Edits, edit)
		}
		resolved.Components = append(resolved.Components, component)
	}
	if len(resolved.Components) != 1 || resolved.Components[0].Profile != ref {
		t.Fatal("raw request does not reference the namespace profile", resolved.Components)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: cluster, Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "namespace", Name: "api-a", UID: "pod", ControllerUID: "replicaset"}, PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "policies", Generation: 1, Digest: artifact.Digest{1}}, Complete: true, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: 600, AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compiler.CompileRecorder(planvalue.RecorderInput{CaptureID: cluster, Executor: identity.Principal{Issuer: "https://identity.example.test", Subject: "requester", ClientID: "console", Kind: identity.Human}, Target: target, Composition: resolved, Retention: retention, Deadline: now.Add(time.Minute), NodeRecorder: true, RequireApproval: true}, recordingCompiler{}, now)
	if err != nil {
		t.Fatal("raw request cannot compile through the actual planner", err)
	}
	if plan.Approval == nil || plan.Approval.DataClass != "raw" || plan.Approval.ObservationLimits == nil || !compiler.AcceptableRecorder(plan).Acceptable() {
		t.Fatal("raw plan lacks raw approval/observation limits or is unacceptable", plan.Approval, compiler.AcceptableRecorder(plan))
	}
	recording, _, err := compiler.RecordingFor(plan)
	if err != nil || recording.Profile != "rawPackets" || recording.Snaplen != 96 || recording.ProtocolSnaplen == nil || recording.ProtocolSnaplen.TCP != manualRawTCPCap || recording.DurationMillis != 5000 || recording.MaxBytes > artifact.RecordingNativeLimit || recording.Filter == nil || !recording.RequireApproval {
		t.Fatalf("raw recording %+v %v", recording, err)
	}
	// The executor recompiles the accepted recording from its frozen
	// composition and program (api_context Check/Compile).
	frozen, err := compiler.RecorderContextFor(&recording)
	if err != nil {
		t.Fatal("frozen raw recorder context", err)
	}
	capability := planvalue.ContextCapability{ExecutionClass: artifact.ContextAPIExecution, Enabled: true, Revision: identity.Revision{UID: "ceiling", Generation: 1, Digest: artifact.Digest{1}}, CollectorVersion: "v1", CollectorImageDigest: artifact.Digest{2}, ProjectionDigest: compiler.ProjectionDigest(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	// Catalog documents are never persisted (REQ-CPR-001): the executor's
	// Profiles port reads the pinned namespace version again for each start.
	executor := planvalue.ContextInput{CaptureID: cluster, Executor: identity.Principal{Issuer: "https://identity.example.test", Subject: "requester", ClientID: "console", Kind: identity.Human}, Deadline: now.Add(time.Minute), Target: target, Capability: capability, Retention: retention, Recorder: frozen}
	if _, err := compiler.CompileContext(executor, now); err == nil {
		t.Fatal("recompiled a namespace profile without reading it")
	}
	frozen.Composition.Resolved = resolved.Resolved
	if _, err := compiler.CompileContext(planvalue.ContextInput{CaptureID: cluster, Executor: identity.Principal{Issuer: "https://identity.example.test", Subject: "requester", ClientID: "console", Kind: identity.Human}, Deadline: now.Add(time.Minute), Target: target, Capability: capability, Retention: retention, Recorder: frozen}, now); err != nil {
		t.Fatal("executor cannot recompile the accepted raw recording", err)
	}
}

// The tshark gate of the manual-raw focus on synthetic field lines.
func TestInstalledManualRawPacketFields(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		ok        bool
	}{
		{"payload kept", "40000,8080\t66\t66\n8080,40000\t200\t412\n", true},
		{"headers only", "40000,8080\t66\t66\n8080,40000\t134\t412\n", false},
		{"over cap", "40000,8080\t201\t412\n", false},
		{"other port", "40000,9090\t200\t412\n", false},
		{"not tcp", "\t200\t412\n", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := checkManualRawFields(tc.out); (err == nil) != tc.ok {
				t.Fatal(tc.name, err)
			}
		})
	}
}
