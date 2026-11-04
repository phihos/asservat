package postgres

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// Real parent/child profile compilers and row decoding, with synthetic current
// endpoint/identity/retention facts. SQL admission is qualified separately.
func compiledPolicyProfileGrant(t *testing.T, requireAll ...bool) (authorization.Grant, planning.ContextPlan) {
	t.Helper()
	p := previewTestValue(t)
	row := compiledProfileReplayRow(t)
	var expected artifact.ContextExpectation
	if err := json.Unmarshal(row.ExpectationJson, &expected); err != nil {
		t.Fatal(err)
	}
	child, err := compiler.ProfileContextFor(expected.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(requireAll) == 1 && requireAll[0] {
		child.RequireApproval = true
		child.Composition.Components[0].Edits = []planning.ProfileEdit{{ActionID: "cpu", Field: "actionMaxBytes", Number: 4 << 20}}
		child.Composition.MaxTotalBytes = 4 << 20
		child.Endpoints[0].Request.NativeLimit = 4 << 20
	}
	r := child.Endpoints[0].Request
	definition := planning.GoEndpointDefinition{Source: planning.GoEndpointSource{ClusterID: r.Target.ClusterID, ResourceUID: p.ID, Name: "go-pprof-loopback", Digest: artifact.Digest{17}}, Host: "localhost", PathPolicy: planning.GoEndpointPathPolicy, AddressModes: []string{"targetLoopback"}, MinimumPort: 6000, MaximumPort: 6999, LoopbackFamily: "ipv4"}
	digest, err := compiler.ProfileEndpointDefinitionDigest(definition)
	if err != nil {
		t.Fatal(err)
	}
	binding := r.Bindings[0]
	pin := &planning.PolicyProfileEndpoint{Definition: definition, DefinitionDigest: digest, SourceRef: r.SourceRef, SourceKind: targets.ProfileEndpointTemplateBinding, AddressMode: binding.AddressMode, Binding: &binding}
	parent, err := compiler.CompilePolicyRecorder(child.Composition, nil, pin)
	if err != nil {
		t.Fatal("actual policy profile parent compiler", err)
	}
	stored := policyGrantTestRow(t)
	g, err := grantFromRow(stored)
	if err != nil {
		t.Fatal(err)
	}
	a := &g.Policy.Authority
	a.Actions, a.Limits = []string{"profile"}, authorization.AutomationLimits{MaxExecutions: 4, MaxBytes: 64 << 20}
	policy := capture.RestartPolicy{ClusterID: a.ClusterID, Namespace: p.Target.Namespace.Name, WorkloadKind: p.Target.Workload.Kind, WorkloadName: p.Target.Workload.Name, Reasons: []string{"Error"}, Interval: time.Minute, Burst: 1, RetentionSeconds: 3600, ObservedPods: 1, Recorder: &parent}
	g.Scope = captureapp.RecorderPolicyScope(a.PolicyUID, 1, artifact.Digest{19}, policy, a.NamespaceUID, a.WorkloadUID, a.Delegation, a.Owners, a.Actions, a.Limits)
	a.ScopeDigest = sha256.Sum256(g.Scope)
	g.ExecutionDigest, g.DataClass, g.Policy.RecipeDigest, g.Policy.Limits = a.ScopeDigest, "raw", parent.RecipeDigest, a.Limits
	g.Reasons = []authorization.SensitiveReason{{ActionID: parent.Action.ID, Code: "policyCollection"}, {ActionID: parent.Action.ID, Code: planning.ReasonLiveProfile}}
	stored.Scope, stored.ExecutionDigest, stored.DataClass = g.Scope, g.ExecutionDigest[:], g.DataClass
	stored.PolicyScope, _ = json.Marshal(g.Policy)
	stored.Reasons, _ = json.Marshal([]grantReasonWire{{ActionID: parent.Action.ID, Code: "policyCollection"}, {ActionID: parent.Action.ID, Code: planning.ReasonLiveProfile}})
	stored.PolicyMaxBytes.Int64, stored.PolicyMaxExecutions.Int64 = g.Policy.Limits.MaxBytes, g.Policy.Limits.MaxExecutions
	g, err = grantFromRow(stored)
	if err != nil {
		t.Fatal("full stored profile grant decoding", err)
	}
	child.Endpoints[0].DefinitionDigest = digest
	target := targets.PodResolution{Request: p.Target, Pin: p.Pin, ExecutionClass: artifact.ContextAPIExecution, PodResourceVersion: "10", WorkloadResourceVersion: "20", ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(5 * time.Second)}
	target.Pin.NodeName = ""
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "set", Generation: 1, Digest: artifact.Digest{7}}, ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "profile", AnchorAt: p.CreatedAt}, p.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	capability := planning.ContextCapability{ExecutionClass: artifact.ContextAPIExecution, Enabled: true, Revision: identity.Revision{UID: "ceiling", Generation: 1, Digest: artifact.Digest{1}}, CollectorVersion: "qualified-fixture", CollectorImageDigest: artifact.Digest{2}, ProjectionDigest: compiler.ProjectionDigest(), ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(5 * time.Second)}
	plan, err := compiler.CompileContext(planning.ContextInput{CaptureID: p.CaptureID, Executor: g.Policy.Authority.Executor, Deadline: p.Deadline, Target: target, Retention: retention, Capability: capability, Profile: child}, p.CreatedAt)
	if err != nil {
		t.Fatal("actual policy profile child compiler", err)
	}
	return g, plan
}

func TestPolicyProfileGrantMatchesProtectedRequireAllAndEditedNativeLimit(t *testing.T) {
	g, plan := compiledPolicyProfileGrant(t, true)
	child, err := compiler.ProfilePlanForContext(plan)
	if err != nil || !slices.Contains(child.Actions[0].Sensitive, planning.ReasonRecordingApproval) || !plan.Input.Profile.RequireApproval {
		t.Fatal("fixture lost protected require-all policy", err)
	}
	acquisition, _, err := compiler.ProfileForContext(plan)
	if err != nil || acquisition.MaxBytes != 4<<20 || !policyProfileAcquisitionMatches(g, &acquisition, plan.RecipeDigest) {
		t.Fatal("edited profile native reservation differs", err)
	}
	if !policyProfilePlanMatches(g, plan) {
		t.Fatal("current protected require-all reason refused an otherwise exact recurring profile")
	}
	if !slices.Contains(child.Actions[0].Sensitive, planning.ReasonRecordingApproval) || !compiler.VerifyFrozenContextPlan(plan) {
		t.Fatal("comparison changed the protected child action or frozen plan")
	}
	var scope map[string]json.RawMessage
	if err := json.Unmarshal(g.Scope, &scope); err != nil {
		t.Fatal(err)
	}
	var policy capture.RestartPolicy
	if err := json.Unmarshal(scope["Policy"], &policy); err != nil {
		t.Fatal(err)
	}
	policy.Recorder.Action.Sensitive = append(slices.Clone(policy.Recorder.Action.Sensitive), planning.ReasonRawPackets)
	scope["Policy"], _ = json.Marshal(policy)
	g.Scope, _ = json.Marshal(scope)
	g.ExecutionDigest = sha256.Sum256(g.Scope)
	g.Policy.Authority.ScopeDigest = g.ExecutionDigest
	if _, err := authapp.PolicyProfileGrantRecorder(g); err != nil {
		t.Fatal("mutated complete scope did not reach action comparison", err)
	}
	if policyProfilePlanMatches(g, plan) {
		t.Fatal("unrelated collection-sensitive reason ignored")
	}
}

func TestPolicyProfileGrantMatchesExactChildAndNativeReservation(t *testing.T) {
	g, plan := compiledPolicyProfileGrant(t)
	if !policyProfilePlanMatches(g, plan) {
		parent, parentErr := authapp.PolicyProfileGrantRecorder(g)
		child, childErr := compiler.ProfilePlanForContext(plan)
		acquisition, _, acquireErr := compiler.ProfileForContext(plan)
		t.Fatalf("matching compiled policy/trigger child refused: parent=%v child=%v acquisition=%v acquisitionMatches=%t recipeMatches=%t parentAction=%+v childActions=%+v profiles=%+v/%+v", parentErr, childErr, acquireErr, policyProfileAcquisitionMatches(g, &acquisition, plan.RecipeDigest), parent.RecipeDigest == plan.RecipeDigest, parent.Action, child.Actions, parent.Profile, child.Profiles)
	}
	acquisition, _, err := compiler.ProfileForContext(plan)
	if err != nil || acquisition.MaxBytes != 16<<20 || !policyProfileAcquisitionMatches(g, &acquisition, plan.RecipeDigest) {
		t.Fatal("current effect lost exact native output ceiling", err)
	}
	for name, change := range map[string]func(*artifact.GoProfileAcquisition){
		"native ceiling": func(p *artifact.GoProfileAcquisition) { p.MaxBytes-- },
		"duration":       func(p *artifact.GoProfileAcquisition) { p.DurationMillis-- },
		"timeout":        func(p *artifact.GoProfileAcquisition) { p.TimeoutMillis++ },
		"type":           func(p *artifact.GoProfileAcquisition) { p.Type = "heap" },
		"mode":           func(p *artifact.GoProfileAcquisition) { p.Mode = "delta" },
		"GC":             func(p *artifact.GoProfileAcquisition) { p.ForceGC = true },
		"source":         func(p *artifact.GoProfileAcquisition) { p.SourceRef = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := acquisition
			change(&changed)
			if policyProfileAcquisitionMatches(g, &changed, plan.RecipeDigest) {
				t.Fatal("changed acquisition covered by original recurring grant")
			}
		})
	}
	for _, field := range []string{"definition", "port", "binding", "workload", "composition"} {
		t.Run(field, func(t *testing.T) {
			changed := acquisition
			child, _ := compiler.ProfileContextFor(&changed)
			switch field {
			case "definition":
				child.Endpoints[0].DefinitionDigest[0]++
			case "port":
				child.Endpoints[0].Port = 7000
			case "binding":
				child.Endpoints[0].Request.Bindings[0].TemplateRef = "other"
			case "workload":
				child.Endpoints[0].Request.Target.Workload.UID = "other"
			case "composition":
				child.Composition.MaxDuration = "31s"
			}
			changed.Composition, _ = json.Marshal(child)
			if policyProfileAcquisitionMatches(g, &changed, plan.RecipeDigest) {
				t.Fatal("changed stable parent/child binding accepted")
			}
		})
	}
}
