package presentation

import (
	"encoding/json"
	"testing"
)

// The presenter already preserves bounded reason strings. This locks in both
// public transports while the acquisition/SQL producer starts supplying the
// newly explicit unavailable reason; no new public operation is introduced.
func TestProfileRefusalProgressKeepsFailedReasonAndNoArtifact(t *testing.T) {
	for _, reason := range []string{"ProfileUnavailable", "ProfilerBusy", "AcquisitionFailed"} {
		t.Run(reason, func(t *testing.T) {
			base, current := operationFixture(t, true)
			p, err := current.Get(t.Context(), current, "00000000-0000-4000-8000-000000000030")
			if err != nil {
				t.Fatal(err)
			}
			p.ActionID, p.Phase, p.ActionPhase, p.ReasonCode = "cpu-profile", "Failed", "Failed", reason
			p.CaseID, p.CanCancel, p.RetryAfterSeconds = "", false, 0
			ops, err := NewContextOperations(base.config, current, groupedRecordingProgressFixture{p})
			if err != nil {
				t.Fatal(err)
			}
			reply, err := ops.Call(t.Context(), current, "get_capture", json.RawMessage(`{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
			if err != nil {
				t.Fatal(err)
			}
			if ops.contracts.ValidateOutput("get_capture", reply.Body) != nil || ops.contracts.ValidateBrowserOutput("get_capture", reply.Body) != nil {
				t.Fatal("MCP/browser closed progress parity")
			}
			var envelope struct{ Data ContextProgressData }
			if json.Unmarshal(reply.Body, &envelope) != nil {
				t.Fatal("progress reply")
			}
			got := envelope.Data
			if got.Phase != "Failed" || len(got.Actions) != 1 || got.Actions[0].Phase != "Failed" || got.Actions[0].ReasonCode != reason || got.Actions[0].ActionID != "cpu-profile" || got.CaseID != "" || got.CanCancel || got.RetryAfterSeconds != 0 {
				t.Fatal("profile refusal lost or turned into evidence/retry", string(reply.Body))
			}
		})
	}
}
