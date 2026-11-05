package postgres

import (
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"encoding/json"
	"testing"
)

func TestProcessesAdmissionUsesExactCompiledCapAndApproval(t *testing.T) {
	for _, required := range []bool{false, true} {
		a := compiledSensitiveAdmission(t, false, false, false)
		in := a.Plan.Input
		in.Recorder = nil
		in.Retention.EvidenceType = "processSnapshot"
		in.Processes = &planvalue.ProcessesContext{Composition: planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "saved", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "inspect-processes", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "processes", Field: "actionMaxBytes", Number: artifact.ProcessNativeLimit}}}}, MaxTotalBytes: artifact.ProcessNativeLimit, MaxDuration: "10s"}, RequireApproval: required}
		var err error
		a.Plan, err = planning.CompileContext(in, a.Plan.CompiledAt)
		if err != nil || !planning.VerifyFrozenContextPlan(a.Plan) {
			t.Fatal("real processes compiler", err)
		}
		l, _, err := planning.ProcessesForContext(a.Plan)
		if err != nil {
			t.Fatal(err)
		}
		a.Registration.NativeLimit = l.MaxNativeBytes
		if !admissionNativeLimit(a) || approvedContextPlan(a) != required {
			t.Fatal("processes cap/approval diverged from compiled plan", required)
		}
		a.Registration.NativeLimit = artifact.RecordingNativeLimit
		if admissionNativeLimit(a) {
			t.Fatal("recording8MiB cap substituted for accepted2MiB processes")
		}
		row := progressFactsFixture(t, "pending").ContextCapture
		var e artifact.ContextExpectation
		if err = json.Unmarshal(row.ExpectationJson, &e); err != nil {
			t.Fatal(err)
		}
		e.ExecutionClass = artifact.ContextAPIExecution
		e.NodeUID, e.NodeBootID = "", ""
		e.NativeType, e.ActionID, e.Processes, e.DataClass = artifact.ProcessesArtifact, l.ActionID, &l, "metadata"
		e.Recording, e.Profile, e.Snapshot, e.Logs = nil, nil, nil, nil
		e.PlanDigest, e.RecipeDigest = a.Plan.ScopeDigest, a.Plan.RecipeDigest
		e.Registration.NativeLimit = l.MaxNativeBytes
		row.ExpectationJson, _ = json.Marshal(e)
		row.ScopeJson = a.Plan.CanonicalScope
		row.ScopeDigest = append([]byte(nil), a.Plan.ScopeDigest[:]...)
		row.PodPinJson, _ = json.Marshal(in.Target.Pin)
		if e.Validate() != nil {
			t.Fatal("exact accepted processes expectation", e.Validate())
		}
		if _, err = requestRecordScope(row); err != nil {
			t.Fatal("accepted processes historical identity", required, err)
		}
	}
}
