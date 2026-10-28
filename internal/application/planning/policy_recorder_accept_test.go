package planning

import (
	"bytes"
	"reflect"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/planning"
)

// This is an inert compiler plan, not accepted authority or a meter permit.
// The manual/public acceptance refusal must remain while the policy companion
// can derive its exact frozen expectation for SQL/current-grant qualification.
func TestFinitePolicyRecorderKeepsRawPlanSeparateFromManualAcceptance(t *testing.T) {
	in, now := recorderInput(t, network(text("sample", "actionExecutionMode", "onTrigger"), text("sample", "packetBefore", "0s"), text("sample", "packetAfter", "1s"), text("sample", "actionTimeout", "10s"), text("sample", "packetFilter", "tcp[13] & 2 != 0")), "packetCapture")
	in.Executor = authorization.PolicyPrincipal("11111111-1111-4111-8111-111111111111", "accepted-policy")
	in.NodeRecorder = true
	in.Target.ExecutionClass, in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = artifact.ContextAPIExecution, "", "", ""
	plan, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
	if err != nil || plan.Approval == nil || plan.Approval.ObservationLimits == nil {
		t.Fatal("inert raw policy review", err)
	}
	if AcceptableRecorder(plan).Acceptable() {
		t.Fatal("manual/shared acceptance enabled raw")
	}
	rec, action, err := RecordingFor(plan)
	if err != nil || !rec.Valid() || rec.RequireApproval || rec.DurationMillis != 1000 || rec.Filter == nil || rec.Filter.Expression != "tcp[13] & 2 != 0" || action != plan.Actions[0].ID {
		t.Fatalf("policy frozen recording: %+v %v", rec, err)
	}
	// RequireApproval preserves the original protected require-all switch; raw
	// sensitivity/grant need comes from the reviewed filter, not a forged setting.
	contextIn, _ := contextInput(t)
	contextIn.Executor = in.Executor
	contextIn.Retention, contextIn.Recorder, contextIn.CaseID, contextIn.Target = in.Retention, nil, "", in.Target
	contextIn.Capability.ExecutionClass = artifact.ContextAPIExecution
	contextIn.Recorder, err = RecorderContextFor(&rec)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := CompileContext(contextIn, now)
	if err != nil || accepted.ScopeDigest != plan.ScopeDigest || !bytes.Equal(accepted.CanonicalScope, plan.CanonicalScope) || !VerifyFrozenContextPlan(accepted) {
		t.Fatal("policy expectation cannot reproduce exact reviewed scope", err)
	}
	again, againAction, err := RecordingForContext(accepted)
	if err != nil || againAction != action || !reflect.DeepEqual(again, rec) {
		t.Fatal("policy immutable recording changed on replay", err)
	}
	ordinary, _ := contextInput(t)
	contextIn.Executor = ordinary.Executor
	if _, err = CompileContext(contextIn, now); err == nil {
		t.Fatal("ordinary actor acquired raw acceptance")
	}
}

func TestFinitePolicyRawContextDeclinesOngoingOrLongSession(t *testing.T) {
	for _, mode := range []string{"ongoing", "long-action"} {
		t.Run(mode, func(t *testing.T) {
			after, timeout := "1s", "10s"
			if mode == "long-action" {
				after, timeout = "16s", "25s"
			}
			edits := []value.ProfileEdit{text("sample", "packetAfter", after), text("sample", "actionTimeout", timeout), text("sample", "packetFilter", "tcp[13] & 2 != 0")}
			if mode != "ongoing" {
				edits = append(edits, text("sample", "actionExecutionMode", "onTrigger"), text("sample", "packetBefore", "0s"))
			}
			composition := network(edits...)
			if mode == "long-action" {
				composition.MaxDuration = "30s"
			}
			in, now := recorderInput(t, composition, "packetCapture")
			in.Executor = authorization.PolicyPrincipal("11111111-1111-4111-8111-111111111111", "accepted-policy")
			in.NodeRecorder = true
			in.Target.ExecutionClass, in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = artifact.ContextAPIExecution, "", "", ""
			plan, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
			if err != nil {
				t.Fatal("inert review should compile before acceptance check", err)
			}
			if contextRecorderAcceptance(plan).Acceptable() {
				t.Fatal("unsupported policy session became acceptable")
			}
			if _, _, err = RecordingFor(plan); err == nil {
				t.Fatal("unsupported policy session derived recording")
			}
		})
	}
}
