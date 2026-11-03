package postgres

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

type reviewedArgumentCompiler struct{}

func (reviewedArgumentCompiler) CompileFilter(string) (planvalue.CompiledFilter, error) {
	return planvalue.CompiledFilter{}, planvalue.ErrInvalid
}
func (reviewedArgumentCompiler) CompileArguments(_ []string, buffers bool, maximum int64) (artifact.RecordingArguments, error) {
	return artifact.RecordingArguments{ProgramDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AccountingRule: artifact.Digest(collector.ArgumentObservationAccountingRule()), MaxProbeBytes: 512, MaxBytesPerEvent: maximum, MaxBytesPerSecond: planvalue.SensitiveMaxBytesPerSecond, CaptureBuffers: buffers}, nil
}

// The normal compiler supplies the immutable review scope. Only mechanism pins
// and target/retention facts are synthetic; this does not exercise a collector.
func compiledReviewedSyscall(t *testing.T, arguments bool) (value.ContextPreview, value.Admission) {
	t.Helper()
	p, a := metadataReviewedBinding(t)
	raw, err := os.ReadFile("../../application/planning/profiles/syscall-activity-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("profile fixture")
	}
	doc["name"] = "reviewed-syscalls"
	action := doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)
	action["executionMode"] = "onTrigger"
	parameters := action["parameters"].(map[string]any)
	parameters["before"], parameters["after"] = "0s", "3s"
	if arguments {
		action["impact"] = "sensitiveRead"
		parameters["mode"] = "arguments"
		parameters["syscalls"] = map[string]any{"mode": "include", "names": []string{"read", "write"}}
		parameters["arguments"] = map[string]any{"maxBytesPerEvent": 128, "captureBuffers": false}
	}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	ref := planvalue.ProfileRef{Catalog: "namespace", Name: "reviewed-syscalls", Version: "v1"}
	composition := planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "calls", Profile: ref}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s", Resolved: []planvalue.CatalogProfile{{Ref: ref, SourceClusterID: p.Target.ClusterID, SourceNamespaceUID: p.Target.Namespace.UID, SourceUID: "profile", Document: raw, Enabled: true}}}
	p.Pin.NodeName = ""
	p.ExecutionClass = artifact.ContextAPIExecution
	target := targets.PodResolution{Request: p.Target, Pin: p.Pin, ExecutionClass: p.ExecutionClass, PodResourceVersion: "10", WorkloadResourceVersion: "20", ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(5 * time.Second)}
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "set", Generation: 1, Digest: [32]byte{7}}, ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "syscallTrace", AnchorAt: p.CreatedAt}, p.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compiler.CompileRecorder(planvalue.RecorderInput{CaptureID: p.CaptureID, Executor: p.Actor, Target: target, Composition: composition, Retention: retention, Deadline: p.Deadline, NodeRecorder: true}, reviewedArgumentCompiler{}, p.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := compiler.AssessRecorder(plan, p.AssessmentID, p.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	p.Intent.Diagnostic = ""
	p.Intent.Composition = &composition
	p.CanonicalScope, p.ScopeDigest, p.AssessmentRulesDigest = plan.CanonicalScope, plan.ScopeDigest, assessment.RulesDigest
	p.Retention = value.ContextRetentionReview{PurposeRef: retention.PurposeRef, RequestedSeconds: retention.RequestedSeconds, MaximumSeconds: retention.MaximumSeconds, DeletionBudgetSeconds: retention.DeletionBudgetSeconds, Policies: retention.Policies}
	a.Plan.CanonicalScope, a.Plan.ScopeDigest = plan.CanonicalScope, plan.ScopeDigest
	a.Plan.Input.Target, a.Plan.Input.Retention = target, retention
	a.Plan.Input.Recorder = &planvalue.RecorderContext{Composition: composition}
	return p, a
}

func TestArgumentReviewedAdmissionPinsAssessmentRules(t *testing.T) {
	p, a := compiledReviewedSyscall(t, true)
	if !reviewedContextMatches(p, a) {
		t.Fatal("actual argument assessment refused")
	}
	p.AssessmentRulesDigest = compiler.RecorderAssessmentRulesDigest()
	if reviewedContextMatches(p, a) {
		t.Fatal("argument review accepted metadata-only rules")
	}
}
