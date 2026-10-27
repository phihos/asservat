package planning

import (
	"bytes"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
)

// ADR-248: a manual networkHeaders plan for an available node recorder is
// acceptable; its recording carries the frozen program; the context plan of
// the acceptance recompiles exactly the reviewed scope without a compiler.
func TestAcceptedRecorderPlanRoundTripsThroughTheContextPlan(t *testing.T) {
	in, now := recorderInput(t, network(text("sample", "packetFilter", "tcp port 8080"), text("sample", "packetAfter", "15s"), text("sample", "actionTimeout", "20s")), "packetCapture")
	in.NodeRecorder = true
	// The installed profile resolves targets through the connector (API class).
	in.Target.ExecutionClass, in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = artifact.ContextAPIExecution, "", "", ""
	compiler := &fakeCompiler{program: fixtureProgram}
	plan, err := CompileRecorder(in, compiler, now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plan.CanonicalScope, []byte(`"acceptance":"nodeRecorder"`)) {
		t.Fatalf("acceptance not recorded: %s", plan.CanonicalScope)
	}
	unavailable := in
	unavailable.NodeRecorder = false
	if other, _ := CompileRecorder(unavailable, &fakeCompiler{program: fixtureProgram}, now); other.ScopeDigest == plan.ScopeDigest {
		t.Fatal("the acceptance mode must enter the plan digest")
	}
	if a := AcceptableRecorder(plan); !a.Acceptable() {
		t.Fatalf("%+v", a)
	}
	rec, actionID, err := RecordingFor(plan)
	if err != nil || actionID != plan.Actions[0].ID || rec.DurationMillis != 15000 || rec.MaxBytes != artifact.RecordingNativeLimit || rec.Filter == nil || len(rec.Filter.Program) != len(fixtureProgram) || rec.Filter.Expression != "tcp port 8080" {
		t.Fatalf("%+v %s %v", rec, actionID, err)
	}
	ctxIn, _ := contextInput(t)
	recorder, err := RecorderContextFor(&rec)
	if err != nil {
		t.Fatal(err)
	}
	ctxIn.Retention, ctxIn.Recorder, ctxIn.CaseID, ctxIn.Target = in.Retention, recorder, "", in.Target
	ctxIn.Capability.ExecutionClass = artifact.ContextAPIExecution
	cp, err := CompileContext(ctxIn, now)
	if err != nil {
		t.Fatal(err)
	}
	if cp.ScopeDigest != plan.ScopeDigest || !bytes.Equal(cp.CanonicalScope, plan.CanonicalScope) || cp.RecipeDigest != plan.RecipeDigest || !VerifyContextPlan(cp, now) || !VerifyFrozenContextPlan(cp) {
		t.Fatal("the context plan of the acceptance differs from the reviewed plan")
	}
	// A changed frozen program changes nothing silently: the plan no longer compiles to the reviewed scope.
	changed := *recorder.Clone()
	changed.Filters[0].Filter.Program[0].K = 13
	ctxIn.Recorder = &changed
	if other, err := CompileContext(ctxIn, now); err == nil && other.ScopeDigest == plan.ScopeDigest {
		t.Fatal("a changed program kept the scope digest")
	}
	// Pod status is unaffected by the optional field.
	pod, _ := contextInput(t)
	if p, err := CompileContext(pod, now); err != nil || p.RecipeDigest != RecipeDigest() {
		t.Fatal(err)
	}
}

func TestOnlyManualNetworkHeadersPlansAreAcceptable(t *testing.T) {
	for name, c := range map[string]value.ProfileComposition{
		"syscalls":   syscalls(),
		"too long":   network(text("sample", "packetAfter", "6m"), text("sample", "actionTimeout", "7m")),
		"retrospect": network(text("sample", "packetAfter", "0s")),
	} {
		in, now := recorderInput(t, c, map[bool]string{true: "syscallTrace", false: "packetCapture"}[name == "syscalls"])
		plan, err := CompileRecorder(in, nil, now)
		if err != nil {
			continue // refused earlier: never acceptable either
		}
		if AcceptableRecorder(plan).Acceptable() {
			t.Errorf("%s acceptable", name)
		}
		if _, _, err := RecordingFor(plan); err == nil {
			t.Errorf("%s produced a recording", name)
		}
	}
	in, now := recorderInput(t, network(text("sample", "actionExecutionMode", "onTrigger"), text("sample", "packetBefore", "0s"), text("sample", "packetAfter", "5s")), "packetCapture")
	plan, err := CompileRecorder(in, nil, now)
	if err != nil || !AcceptableRecorder(plan).Acceptable() {
		t.Fatal("the onTrigger before:0s variant is a manual capture too", err)
	}
	if rec, _, err := RecordingFor(plan); err != nil || rec.Filter != nil || rec.DurationMillis != 5000 {
		t.Fatal(rec, err)
	}
	_ = time.Second
}

// ADR-248 with ADR-249: the installation's approval switch is frozen into the
// recording, so the accepted context plan reproduces the approved digest; a
// raw byte predicate (observation limits) is not recordable.
func TestRecorderApprovalSurvivesAcceptance(t *testing.T) {
	in, now := recorderInput(t, network(text("sample", "packetFilter", "tcp port 8080"), text("sample", "packetAfter", "5s")), "packetCapture")
	in.NodeRecorder, in.RequireApproval = true, true
	in.Target.ExecutionClass, in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = artifact.ContextAPIExecution, "", "", ""
	plan, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
	if err != nil || plan.Approval == nil || !AcceptableRecorder(plan).Acceptable() {
		t.Fatal(plan.Approval, err)
	}
	fromScope, err := RecorderContextFromScope(in.Composition, plan.CanonicalScope)
	if err != nil || !fromScope.RequireApproval {
		t.Fatal("scope lost the approval switch", err)
	}
	rec, _, err := RecordingFor(plan)
	if err != nil || !rec.RequireApproval {
		t.Fatal(rec, err)
	}
	recorder, err := RecorderContextFor(&rec)
	if err != nil {
		t.Fatal(err)
	}
	ctxIn, _ := contextInput(t)
	ctxIn.Retention, ctxIn.Recorder, ctxIn.CaseID, ctxIn.Target = in.Retention, recorder, "", in.Target
	ctxIn.Capability.ExecutionClass = artifact.ContextAPIExecution
	if cp, err := CompileContext(ctxIn, now); err != nil || cp.ScopeDigest != plan.ScopeDigest {
		t.Fatal("accepted plan differs from the approved plan", err)
	}
	in.RequireApproval = false
	in.Composition = network(text("sample", "packetFilter", "tcp[13] & 2 != 0"), text("sample", "packetAfter", "5s"))
	raw, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
	if err != nil || raw.Approval == nil || AcceptableRecorder(raw).Acceptable() {
		t.Fatal("raw byte predicate recordable", err)
	}
}

// ADR-252: an approved plan's digest binds its finite action duration and
// exact target, while admission fixes a separate execution deadline.
func TestApprovedRecorderPlanSeparatesPreviewFromExecutionDeadline(t *testing.T) {
	in, now := recorderInput(t, network(text("sample", "packetAfter", "15s"), text("sample", "actionTimeout", "20s")), "packetCapture")
	in.NodeRecorder, in.RequireApproval = true, true
	in.Target.ExecutionClass, in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = artifact.ContextAPIExecution, "", "", ""
	reviewed, err := CompileRecorder(in, nil, now)
	if err != nil || !RecorderApprovedAcceptance(reviewed.CanonicalScope) {
		t.Fatal("unmarked approval plan", err)
	}
	later := now.Add(10 * time.Minute)
	in.Deadline = later.Add(4 * time.Minute)
	in.Target.ObservedAt, in.Target.FreshUntil = later, later.Add(5*time.Second)
	in.Retention.ValidUntil = later.Add(5 * time.Second)
	// Retention is relative in the review; current policy/proof is separately read.
	in.Retention.AnchorAt = later
	in.Retention.ExpiresAt = later.Add(time.Duration(min(in.Retention.RequestedSeconds, in.Retention.MaximumSeconds-in.Retention.DeletionBudgetSeconds)) * time.Second)
	in.Retention.DeleteBy = in.Retention.ExpiresAt.Add(time.Duration(in.Retention.DeletionBudgetSeconds) * time.Second)
	ctxIn, _ := contextInput(t)
	ctxIn.CaptureID, ctxIn.CaseID, ctxIn.Executor, ctxIn.Deadline, ctxIn.Target, ctxIn.Retention = in.CaptureID, "", in.Executor, in.Deadline, in.Target, in.Retention
	ctxIn.Capability.ExecutionClass = artifact.ContextAPIExecution
	ctxIn.Capability.ObservedAt, ctxIn.Capability.FreshUntil = later, later.Add(5*time.Second)
	ctxIn.Recorder, err = RecorderContextFromScope(in.Composition, reviewed.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := CompileContext(ctxIn, later)
	if err != nil || accepted.ScopeDigest != reviewed.ScopeDigest || !bytes.Equal(accepted.CanonicalScope, reviewed.CanonicalScope) || !VerifyContextPlan(accepted, later) {
		t.Fatal("approved plan did not survive review wait", err)
	}
	if !accepted.Input.Recorder.RequireApproval {
		t.Fatal("clone lost the approval requirement")
	}
	scope, err := ReadContextScopeIdentity(accepted.CanonicalScope, accepted.ScopeDigest)
	if err != nil || !scope.ApprovedAcceptance || !scope.Deadline.IsZero() {
		t.Fatal("scope timing", err)
	}
	ctxIn.Target.Request.PodUID = "replacement"
	if changed, err := CompileContext(ctxIn, later); err == nil && changed.ScopeDigest == reviewed.ScopeDigest {
		t.Fatal("a replacement Pod inherited approval")
	}
}
