package planning

import (
	"bytes"
	"testing"

	value "asservat.local/asservat/internal/domain/planning"
)

// ADR-249: a raw byte predicate or the installation's recording-approval
// switch makes the compiled plan need an individual approval, bound into the
// execution digest; an ordinary metadata plan is unchanged.
func TestRecorderApprovalRequirement(t *testing.T) {
	c := &fakeCompiler{program: fixtureProgram}
	in, now := recorderInput(t, network(text("sample", "packetFilter", "tcp port 80")), "packetCapture")
	plain, err := CompileRecorder(in, c, now)
	if err != nil || plain.Approval != nil || bytes.Contains(plain.CanonicalScope, []byte(`"approval"`)) {
		t.Fatalf("metadata plan needs approval: %+v %v", plain.Approval, err)
	}
	in, _ = recorderInput(t, network(text("sample", "packetFilter", "tcp[13] & 2 != 0")), "packetCapture")
	raw, err := CompileRecorder(in, c, now)
	if err != nil || raw.Approval == nil || len(raw.Approval.Reasons) != 1 || raw.Approval.Reasons[0].Code != value.ReasonRawBytePredicate || raw.Approval.Reasons[0].ActionID != raw.Actions[0].ID {
		t.Fatalf("raw predicate approval: %+v %v", raw.Approval, err)
	}
	l := raw.Approval.ObservationLimits
	if l == nil || l.MaxSessionSeconds != 15 || l.MaxObservedBytes != value.SensitiveMaxObservedBytes || l.MaxBytesPerSecond != value.SensitiveMaxBytesPerSecond || l.MaxConcurrentSessions != 1 || raw.Approval.DataClass != "extract" {
		t.Fatalf("observation limits: %+v", l)
	}
	if raw.ScopeDigest == plain.ScopeDigest || !VerifyRecorderPlan(raw, c, now) {
		t.Fatal("approval requirement is not part of the execution digest")
	}
	actions, approval, err := RecorderScopeSummary(raw.CanonicalScope)
	if err != nil || approval == nil || len(actions) != 1 || actions[0].Filter != "tcp[13] & 2 != 0" || actions[0].FilterDigest != FilterProgramDigest(fixtureProgram) || actions[0].FilterInstructions != 4 || len(actions[0].Sensitive) != 1 || approval.ObservationLimits.MaxSessionSeconds != 15 {
		t.Fatalf("summary round trip: %+v %+v %v", actions, approval, err)
	}
	if _, approval, err := RecorderScopeSummary(plain.CanonicalScope); err != nil || approval != nil {
		t.Fatal("metadata summary", approval, err)
	}
	// The installation's switch requires approval of a metadata recording,
	// without observation limits (no payload reaches a predicate).
	in, _ = recorderInput(t, syscalls(), "syscallTrace")
	in.RequireApproval = true
	required, err := CompileRecorder(in, c, now)
	if err != nil || required.Approval == nil || required.Approval.Reasons[0].Code != value.ReasonRecordingApproval || required.Approval.ObservationLimits != nil {
		t.Fatalf("installation requirement: %+v %v", required.Approval, err)
	}
	in.RequireApproval = false
	free, err := CompileRecorder(in, c, now)
	if err != nil || free.ScopeDigest == required.ScopeDigest {
		t.Fatal("the installation requirement is not bound into the digest")
	}
	if _, _, err := RecorderScopeSummary([]byte(`{"schemaVersion":"other"}`)); err == nil {
		t.Fatal("foreign document summarized")
	}
}
