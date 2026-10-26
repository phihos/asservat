package presentation

import (
	"fmt"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-231: an alert occurrence reports its alert start as failed_at, and the
// output schema accepts the alert detector.
func TestPolicyStatusReportsAlertOccurrences(t *testing.T) {
	f := &policyOperationsFixture{scopes: []string{"evidence:read"}}
	s, err := NewPolicyOperations("https://asservat.example.invalid", time.Now, func() string { return "88888888-8888-4888-8888-888888888888" }, f, f, f)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	f.status = value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: "99999999-9999-4999-8999-999999999999", Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, MaxExecutions: 10, NotAfter: time.Now().Add(time.Hour),
		Detector: &value.PolicyDetector{Kind: "alert"},
		Recent:   []value.PolicyOccurrenceStatus{{ID: "11111111-1111-4111-8111-111111111111", Outcome: "captured", CaptureID: "22222222-2222-4222-8222-222222222222", Detector: "alert", Restarts: created.Add(-time.Minute).Unix(), CreatedAt: created}}}
	out := policyCall(t, s, f, "get_policy_status", `{"policy_name":"alerts"}`)
	data, _ := out["data"].(map[string]any)
	detector, _ := data["detector"].(map[string]any)
	recent, _ := data["recent"].([]any)
	if out["status"] != "ok" || detector["kind"] != "alert" || len(recent) != 1 {
		t.Fatal("alert status", out)
	}
	if o := recent[0].(map[string]any); o["detector"] != "alert" || o["failed_at"] != "2026-10-26T11:59:00Z" || o["restarts"] != nil {
		t.Fatal("alert occurrence", o)
	}
}

// A region without an Alertmanager refuses an alert policy's activation with
// a fixed, actionable reason.
func TestPolicyActivationNamesMissingAlertmanager(t *testing.T) {
	f := publicPolicyFailure(fmt.Errorf("workload: %w", targets.ErrUnsupported))
	if f.Code != "DetectorUnavailable" || f.Retryable {
		t.Fatal(f)
	}
}
