package planning

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
	"testing"
)

func processComposition() value.ProfileComposition {
	c := network()
	c.Components[0].Profile.Name = "inspect-processes"
	c.MaxTotalBytes = artifact.ProcessNativeLimit
	return c
}

func TestProcessDiscoveryBuiltinUsesExistingCaptureCompiler(t *testing.T) {
	a, _, e := expand(processComposition(), nil, nil)
	if e != nil || len(a) != 1 || a[0].action.Kind != "processSnapshot" {
		t.Fatal("whole-Pod process discovery not usable through catalog compiler", e)
	}
}

func TestProcessDiscoveryAcceptedContextPinsNativeAndApproval(t *testing.T) {
	in, now := contextInput(t)
	in.Target.ExecutionClass, in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = artifact.ContextAPIExecution, "", "", ""
	in.Capability.ExecutionClass = artifact.ContextAPIExecution
	in.Retention.EvidenceType = "processSnapshot"
	in.Processes = &value.ProcessesContext{Composition: processComposition()}
	for _, required := range []bool{false, true} {
		in.Processes.RequireApproval = required
		p, e := CompileContext(in, now)
		if e != nil || !VerifyContextPlan(p, now) {
			t.Fatal("accepted process plan", e)
		}
		r, e := ProcessesPlanForContext(p)
		if e != nil || (r.Approval != nil) != required {
			t.Fatal("ordinary or protected collection review changed", e)
		}
		capture, id, e := ProcessesForContext(p)
		if e != nil || capture.ActionID != id || capture.Mode != artifact.ProcessAll || capture.TimeoutMillis != 5000 || capture.MaxNativeBytes != artifact.ProcessNativeLimit {
			t.Fatal(capture, e)
		}
		restored, e := ProcessesContextFor(&capture)
		if e != nil || restored.RequireApproval != required {
			t.Fatal("immutable context restore", e)
		}
		capture.MaxNativeBytes--
		if _, e := ProcessesContextFor(&capture); e == nil {
			t.Fatal("changed output bound accepted")
		}
		if _, e := AssessRecorder(r, "00000000-0000-4000-8000-000000000099", now); e != nil {
			t.Fatal("metadata assessment", e)
		}
	}
}
