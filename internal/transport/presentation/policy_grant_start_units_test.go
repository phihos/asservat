package presentation

import (
	value "asservat.local/asservat/internal/domain/capture"
	"testing"
	"time"
)

func TestPolicyStatusProjectsServerGrantStartsWithoutChangingSaveCounter(t *testing.T) {
	f := &policyOperationsFixture{scopes: []string{"evidence:read"}, status: value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: "99999999-9999-4999-8999-999999999999", Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, MaxExecutions: 1, MaxCollectedBytes: 1048576, MaxObservedBytes: 8192, NotAfter: time.Now().Add(time.Hour)}}
	s, err := NewPolicyOperations("https://asservat.example.invalid", time.Now, func() string { return "88888888-8888-4888-8888-888888888888" }, f, f, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, starts := range []int64{2, 7, 10000, 0} {
		f.status.MaxGrantStarts = starts
		out := policyCall(t, s, f, "get_policy_status", `{"policy_name":"recording"}`)
		data := out["data"].(map[string]any)
		if data["max_executions"] != float64(1) {
			t.Fatal("source starts changed onceperSave policycounter", data)
		}
		if starts == 0 {
			if _, ok := data["max_grant_starts"]; ok {
				t.Fatal("legacy/unknown ceiling becameinventedguidance", data)
			}
		} else if data["max_grant_starts"] != float64(starts) {
			t.Fatal("server source-start ceiling dropped or recomputed", data, starts)
		}
	}
}
