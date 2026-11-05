package postgres

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

type sensitiveApprovalFilter struct{}

func (sensitiveApprovalFilter) CompileFilter(string) (value.CompiledFilter, error) {
	return value.CompiledFilter{LinkType: value.FilterLinkType, Snaplen: value.FilterSnaplen, Program: []value.BPFInstruction{{Code: 0x06, K: 65535}}}, nil
}

// The real profile/recorder/context compilers supply approval and timing. Only
// the filter mechanism and current target/retention inputs are synthetic.
func compiledSensitiveAdmission(t *testing.T, raw, required, policy bool) capture.Admission {
	t.Helper()
	p, _ := metadataReviewedBinding(t)
	document, err := os.ReadFile("../../application/planning/profiles/network-connections-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(document, &doc) != nil {
		t.Fatal("network profile")
	}
	doc["name"] = "sensitive-packets"
	action := doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)
	if raw {
		action["impact"] = "sensitiveRead"
		action["parameters"].(map[string]any)["profile"] = map[string]any{"kind": "rawPackets", "snaplen": 96}
	}
	document, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	ref := value.ProfileRef{Catalog: "namespace", Name: "sensitive-packets", Version: "v1"}
	expression := "tcp dst port 80"
	if policy {
		expression = "tcp[13] & 16 != 0"
	}
	edits := []value.ProfileEdit{{ActionID: "sample", Field: "packetFilter", Text: expression}, {ActionID: "sample", Field: "actionExecutionMode", Text: "onTrigger"}, {ActionID: "sample", Field: "packetBefore", Text: "0s"}, {ActionID: "sample", Field: "packetAfter", Text: "2s"}, {ActionID: "sample", Field: "actionTimeout", Text: "10s"}}
	c := value.ProfileComposition{Components: []value.ProfileComponent{{ID: "net", Profile: ref, Edits: edits}}, Resolved: []value.CatalogProfile{{Ref: ref, SourceClusterID: p.Target.ClusterID, SourceNamespaceUID: p.Target.Namespace.UID, SourceUID: "sensitive-profile", Document: document, Enabled: true}}, MaxTotalBytes: 16 << 20, MaxDuration: "10s"}
	target := targets.PodResolution{Request: p.Target, Pin: p.Pin, ExecutionClass: artifact.ContextAPIExecution, PodResourceVersion: "10", WorkloadResourceVersion: "20", ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(5 * time.Second)}
	target.Pin.NodeName = ""
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "set", Generation: 1, Digest: artifact.Digest{1}}, ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", AnchorAt: p.CreatedAt}, p.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	actor := p.Actor
	if policy {
		actor = authorization.PolicyPrincipal(p.InstallationID, "sensitive-policy")
	}
	recorder, err := planning.CompileRecorder(value.RecorderInput{CaptureID: p.CaptureID, Executor: actor, Target: target, Composition: c, Retention: retention, Deadline: p.Deadline, NodeRecorder: true, RequireApproval: required}, sensitiveApprovalFilter{}, p.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := planning.RecorderContextFromScope(c, recorder.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	in := value.ContextInput{CaptureID: p.CaptureID, Executor: actor, Target: target, Retention: retention, Deadline: p.Deadline, Recorder: frozen}
	in.Capability = value.ContextCapability{ExecutionClass: artifact.ContextAPIExecution, Enabled: true, Revision: identity.Revision{UID: "qualified", Generation: 1, Digest: artifact.Digest{3}}, CollectorVersion: "fixture", CollectorImageDigest: artifact.Digest{4}, ProjectionDigest: artifact.Digest{5}, ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(5 * time.Second)}
	plan, err := planning.CompileContext(in, p.CreatedAt)
	if err != nil {
		t.Fatal("compiled sensitive context", err)
	}
	if frozen.RequireApproval != required || !planning.VerifyFrozenContextPlan(plan) {
		t.Fatal("fixture did not preserve original require-all setting/frozenplan")
	}
	return capture.Admission{Plan: plan}
}

func TestSensitiveRecorderApprovalIgnoresRequireAllSwitch(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		raw, required, policy, want bool
	}{{"raw-switch-off", true, false, false, true}, {"raw-switch-on", true, true, false, true}, {"ordinary-switch-off", false, false, false, false}, {"ordinary-switch-on", false, true, false, true}, {"policy-predicate-switch-off", false, false, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			a := compiledSensitiveAdmission(t, tc.raw, tc.required, tc.policy)
			if got := approvedContextPlan(a); got != tc.want {
				t.Fatalf("independent compiled approval=%t want=%t requireAll=%t", got, tc.want, tc.required)
			}
		})
	}
	_, arguments := compiledReviewedSyscall(t, true)
	if !approvedContextPlan(arguments) {
		t.Fatal("syscall argument approval skipped when require-all off")
	}
	_, ordinary := compiledReviewedSyscall(t, false)
	if approvedContextPlan(ordinary) {
		t.Fatal("ordinary metadata unexpectedly requires grant")
	}
	// Actual profile compilation retains its independent approval requirement.
	profileRow := compiledProfileReplayRow(t)
	var expected artifact.ContextExpectation
	if json.Unmarshal(profileRow.ExpectationJson, &expected) != nil || expected.Profile == nil {
		t.Fatal("profile fixture")
	}
	var frozen value.ProfileContext
	if json.Unmarshal(expected.Profile.Composition, &frozen) != nil {
		t.Fatal("profile frozen input")
	}
	profile := capture.Admission{Plan: value.ContextPlan{Input: value.ContextInput{Profile: &frozen}, CanonicalScope: profileRow.ScopeJson}}
	if !approvedContextPlan(profile) {
		t.Fatal("profile independent approval lost")
	}
	raw := compiledSensitiveAdmission(t, true, false, false)
	noRecorder := raw
	noRecorder.Plan.Input.Recorder = nil
	if approvedContextPlan(noRecorder) {
		t.Fatal("unrelated context accepted recorder timing")
	}
	// A legacy absolute deadline is not a prospective approved-acceptance scope.
	var legacy map[string]json.RawMessage
	_ = json.Unmarshal(raw.Plan.CanonicalScope, &legacy)
	delete(legacy, "timing")
	legacy["deadline"] = json.RawMessage(`"2026-11-05T00:00:00Z"`)
	raw.Plan.CanonicalScope, _ = json.Marshal(legacy)
	if approvedContextPlan(raw) {
		t.Fatal("legacy absolute scope relabeled approved")
	}
	raw.Plan.CanonicalScope = []byte(`{`)
	if approvedContextPlan(raw) {
		t.Fatal("malformed scope accepted")
	}
}
