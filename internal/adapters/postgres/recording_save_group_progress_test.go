package postgres

import (
	value "asservat.local/asservat/internal/domain/capture"
	"testing"
)

func TestRecordingGroupPhasePreservesActiveAndUsefulUncertainChildren(t *testing.T) {
	for _, tc := range []struct {
		states []string
		want   string
	}{
		{[]string{"Succeeded", "Running"}, "Running"},
		{[]string{"Succeeded", "Pending"}, "Pending"},
		{[]string{"Failed", "Finalizing"}, "Finalizing"},
		{[]string{"Succeeded", "Succeeded"}, "Succeeded"},
		{[]string{"Succeeded", "Cancelled"}, "Partial"},
		{[]string{"Succeeded", "Indeterminate"}, "Partial"},
		{[]string{"Failed", "Indeterminate"}, "Indeterminate"},
		{[]string{"Cancelled", "Cancelled"}, "Cancelled"},
		{[]string{"Failed", "Cancelled"}, "Failed"},
	} {
		actions := make([]value.ContextActionProgress, len(tc.states))
		for n, phase := range tc.states {
			actions[n].Phase = phase
		}
		if phase, _ := recordingGroupPhase(actions); phase != tc.want {
			t.Fatalf("states=%v got=%s want=%s", tc.states, phase, tc.want)
		}
		for n := range actions {
			if actions[n].Phase != tc.states[n] {
				t.Fatal("aggregation changed child truth")
			}
		}
	}
}
