package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/httpheaders"
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
	t.Setenv("ASSERVAT_PROFILE_TRANSPORT", "http")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "")
	for _, tc := range []struct {
		focus    string
		clusters int
		fast     bool
	}{
		{"approved-recording", 2, true}, {"manual-syscall", 2, true}, {"manual-arguments", 2, true}, {"manual-mixed", 2, true}, {"manual-raw", 2, true}, {"manual-http", 2, true}, {"manual-peers", 2, true}, {"manual-profile", 2, true}, {"profile-comparison", 2, true}, {"policy-recording", 2, true}, {"policy-arguments", 2, true}, {"policy-profile", 2, true}, {"ongoing-save", 2, true}, {"ongoing-save-disk", 2, true}, {"ongoing-incident", 2, true}, {"ongoing-syscall", 2, true}, {"ongoing-mixed", 2, true}, {"native-paced", 2, true}, {"journey", 2, true}, {"browser", 2, true},
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
			wantRecording := tc.focus == "approved-recording" || tc.focus == "manual-syscall" || tc.focus == "manual-arguments" || tc.focus == "manual-mixed" || tc.focus == "manual-raw" || tc.focus == "manual-http" || tc.focus == "manual-peers" || tc.focus == "manual-profile" || tc.focus == "profile-comparison" || tc.focus == "native-paced" || tc.focus == "policy-recording" || tc.focus == "policy-arguments" || tc.focus == "policy-profile" || tc.focus == "ongoing-save" || tc.focus == "ongoing-save-disk" || tc.focus == "ongoing-incident" || tc.focus == "ongoing-syscall" || tc.focus == "ongoing-mixed"
			if got := installedRecordingFocus(); got != wantRecording {
				t.Fatalf("recording focus parent-return guard=%v; want %v", got, wantRecording)
			}
			if got, want := installedApprovedRecordingExpiryProof(tc.focus), tc.focus != "profile-comparison"; got != want {
				t.Fatalf("manual preview expiry proof=%v; want %v", got, want)
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

// The installed qualification must consume the actual advisory choices instead
// of silently authoring an operation that the production preview never offered.
func TestInstalledApprovedRecordingDecodesResultAccessChoices(t *testing.T) {
	input := []byte(`{"result_access_actions":[{"action_id":"arguments","operations":["download_artifact","syscall_query"]}]}`)
	var preview installedApprovedRecordingPreview
	if err := json.Unmarshal(input, &preview); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(preview)
	if err != nil || !bytes.Contains(raw, []byte(`"result_access_actions":[{"action_id":"arguments","operations":["download_artifact","syscall_query"]}]`)) {
		t.Fatal("installed helper discarded actual preview operations", err)
	}
}

func TestInstalledApprovedRecordingRequiresOfferedArgumentsChoice(t *testing.T) {
	want := []string{"download_artifact", "syscall_query"}
	for _, tc := range []struct {
		name, choices string
		want          bool
	}{
		{"offered", `[{"action_id":"arguments","operations":["download_artifact","syscall_query"]}]`, true},
		{"missing", `[]`, false},
		{"different-action", `[{"action_id":"other","operations":["download_artifact","syscall_query"]}]`, false},
		{"download-only", `[{"action_id":"arguments","operations":["download_artifact"]}]`, false},
		{"packet-choice", `[{"action_id":"arguments","operations":["download_artifact","pcap_query"]}]`, false},
		{"extra-operation", `[{"action_id":"arguments","operations":["download_artifact","pcap_query","syscall_query"]}]`, false},
		{"duplicate", `[{"action_id":"arguments","operations":["download_artifact","syscall_query"]},{"action_id":"arguments","operations":["download_artifact","syscall_query"]}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var preview installedApprovedRecordingPreview
			if err := json.Unmarshal([]byte(`{"result_access_actions":`+tc.choices+`}`), &preview); err != nil {
				t.Fatal(err)
			}
			operations, ok := preview.resultAccessOperations("arguments", want)
			if ok != tc.want || ok && !slices.Equal(operations, want) {
				t.Fatal("submitted unoffered arguments operations", operations, ok)
			}
			if ok {
				operations[0] = "changed"
				if preview.ResultAccessActions[0].Operations[0] != "download_artifact" || want[0] != "download_artifact" {
					t.Fatal("submission mutated original preview choice")
				}
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

// ADR-282 manual-http focus: the public request is valid, and the published
// namespace definition compiles through the actual planner (synthetic facts,
// test filter compiler; no capture) into an acceptable HTTP header recording
// with extract approval, observation limits and the reviewed parser bounds.
func TestInstalledManualHTTPRequestCompiles(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-http")
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
		t.Fatal("manual HTTP request is not a public capture input", err)
	}
	definition, err := manualHTTPProfileDefinition()
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(map[string]any{"name": manualHTTPProfileName, "version": manualHTTPProfileVersion, "definition": definition})
	if err != nil {
		t.Fatal(err)
	}
	compositionJSON, _ := json.Marshal(input["profile_composition"])
	var public presentation.CompositionInput
	if err := json.Unmarshal(compositionJSON, &public); err != nil {
		t.Fatal(err)
	}
	ref := planvalue.ProfileRef{Catalog: "namespace", Name: manualHTTPProfileName, Version: manualHTTPProfileVersion}
	resolved := planvalue.ProfileComposition{MaxTotalBytes: public.MaxTotalBytes, MaxDuration: public.MaxDuration,
		Resolved: []planvalue.CatalogProfile{{Ref: ref, SourceClusterID: cluster, SourceNamespaceUID: "namespace", SourceUID: "http-capture-uid", Document: document, Enabled: true}}}
	for _, c := range public.Components {
		component := planvalue.ProfileComponent{ID: c.ID, Profile: planvalue.ProfileRef{Catalog: c.ProfileRef.Catalog, Name: c.ProfileRef.Name, Version: c.ProfileRef.Version}}
		for _, o := range c.Overrides {
			edit := planvalue.ProfileEdit{ActionID: o.ActionID, Field: o.Field}
			if err := json.Unmarshal(o.Value, &edit.Text); err != nil {
				t.Fatal("HTTP override", o.Field, err)
			}
			component.Edits = append(component.Edits, edit)
		}
		resolved.Components = append(resolved.Components, component)
	}
	if len(resolved.Components) != 1 || resolved.Components[0].Profile != ref {
		t.Fatal("HTTP request does not reference the namespace profile", resolved.Components)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: cluster, Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "namespace", Name: "api-a", UID: "pod", ControllerUID: "replicaset"}, PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "policies", Generation: 1, Digest: artifact.Digest{1}}, Complete: true, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: 600, AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compiler.CompileRecorder(planvalue.RecorderInput{CaptureID: cluster, Executor: identity.Principal{Issuer: "https://identity.example.test", Subject: "requester", ClientID: "console", Kind: identity.Human}, Target: target, Composition: resolved, Retention: retention, Deadline: now.Add(time.Minute), NodeRecorder: true, RequireApproval: true}, recordingCompiler{}, now)
	if err != nil {
		t.Fatal("HTTP request cannot compile through the actual planner", err)
	}
	if _, ok := input["result_access"]; ok {
		t.Fatal("HTTP request carries result_access")
	}
	if plan.Approval == nil || plan.Approval.DataClass != "extract" || plan.Approval.ObservationLimits == nil || !compiler.AcceptableRecorder(plan).Acceptable() {
		t.Fatal("HTTP plan lacks extract approval/observation limits or is unacceptable", plan.Approval, compiler.AcceptableRecorder(plan))
	}
	t.Logf("HTTP observation limits %+v", *plan.Approval.ObservationLimits)
	recording, _, err := compiler.RecordingFor(plan)
	l := manualHTTPLimits()
	want := artifact.RecordingHTTP{MaxFlows: l.MaxFlows, MaxHeaderBytes: l.MaxHeaderBytes, MaxFlowBytes: l.MaxFlowBytes, MaxTotalBytes: l.MaxTotalBytes, IdleMillis: l.IdleTimeout.Milliseconds()}
	if err != nil || recording.Profile != "httpHeaders" || recording.Snaplen != httpheaders.Snaplen || recording.HTTP == nil || *recording.HTTP != want || recording.ProtocolSnaplen != nil || recording.DurationMillis != 5000 || recording.MaxBytes > artifact.RecordingNativeLimit || recording.Filter == nil || !recording.RequireApproval {
		t.Fatalf("HTTP recording %+v %v", recording, err)
	}
	// The executor recompiles the accepted recording from its frozen
	// composition and program (api_context Check/Compile).
	frozen, err := compiler.RecorderContextFor(&recording)
	if err != nil {
		t.Fatal("frozen HTTP recorder context", err)
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
		t.Fatal("executor cannot recompile the accepted HTTP recording", err)
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

// The projection gate of the manual-http focus on synthetic projections.
func TestInstalledManualHTTPProjectionFields(t *testing.T) {
	l := manualHTTPLimits()
	start := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	projection := func(records ...httpheaders.Record) httpheaders.Projection {
		p := httpheaders.Projection{Format: artifact.HTTPHeadersFormat, Protocol: "http1", StartedAt: start, EndedAt: start.Add(5 * time.Second), Records: records,
			Limits: httpheaders.LimitsRecord{MaxFlows: l.MaxFlows, MaxHeaderBytes: l.MaxHeaderBytes, MaxFlowBytes: l.MaxFlowBytes, MaxTotalBytes: l.MaxTotalBytes, IdleTimeoutSeconds: 30, Snaplen: httpheaders.Snaplen}}
		p.Counters.Records = uint64(len(records))
		return p
	}
	encode := func(p httpheaders.Projection) []byte {
		b, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	answered := httpheaders.Record{Timestamp: start.Add(time.Second), Method: "GET", Status: 200, Headers: []httpheaders.Header{{Name: "content-type", Value: "text/plain; charset=utf-8"}, {Name: "content-length", Value: "3"}}}
	good := encode(projection(answered))
	otherProtocol := projection(answered)
	otherProtocol.Protocol = "http2"
	otherLimits := projection(answered)
	otherLimits.Limits.MaxFlows = 1
	for _, tc := range []struct {
		name string
		doc  []byte
		ok   bool
	}{
		{"answered GET", good, true},
		{"no records", encode(projection()), false},
		{"partial only", encode(projection(httpheaders.Record{Timestamp: start.Add(time.Second), Method: "GET", Headers: []httpheaders.Header{}, Partial: true})), false},
		{"other protocol", encode(otherProtocol), false},
		{"other limits", encode(otherLimits), false},
		{"unknown field", append(good[:len(good)-1:len(good)-1], []byte(`,"cookie":"x"}`)...), false},
		{"trailing data", append(append([]byte(nil), good...), []byte(" {}")...), false},
		{"marker", bytes.Replace(good, []byte(`"text/plain`), []byte(`"`+manualHTTPMarker), 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := checkManualHTTPProjection(tc.doc); (err == nil) != tc.ok {
				t.Fatal(tc.name, err)
			}
		})
	}
}
