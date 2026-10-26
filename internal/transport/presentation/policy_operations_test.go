package presentation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type policyOperationsFixture struct {
	scopes  []string
	stopped int
	status  value.PolicyStatus
}

func (f *policyOperationsFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	now := time.Now()
	return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}, Scopes: f.scopes, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}, nil
}
func (f *policyOperationsFixture) Activate(context.Context, identities.CurrentIdentity, string, string) (app.PolicyActivationResult, error) {
	return app.PolicyActivationResult{}, app.ErrPolicyDeactivated
}
func (f *policyOperationsFixture) Get(context.Context, identities.CurrentIdentity, string) (value.PolicyStatus, time.Time, error) {
	return f.status, time.Now().Add(5 * time.Second), nil
}
func (f *policyOperationsFixture) Deactivate(context.Context, identities.CurrentIdentity, string) (app.PolicyDeactivationResult, error) {
	f.stopped++
	return app.PolicyDeactivationResult{PolicyUID: "policy-uid", AcceptanceID: "99999999-9999-4999-8999-999999999999", Replay: f.stopped > 1}, nil
}

func policyCall(t *testing.T, s *PolicyOperations, f *policyOperationsFixture, name, input string) map[string]any {
	t.Helper()
	reply, err := s.CallWithContext(context.Background(), f, OperationCall{requestID: "88888888-8888-4888-8888-888888888888"}, name, json.RawMessage(input))
	if err != nil {
		t.Fatal(name, err)
	}
	var out map[string]any
	if err := json.Unmarshal(reply.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPolicyDeactivationOperationContract(t *testing.T) {
	f := &policyOperationsFixture{scopes: []string{"evidence:read", "evidence:capture"}}
	s, err := NewPolicyOperations("https://asservat.example.invalid", time.Now, func() string { return "88888888-8888-4888-8888-888888888888" }, f, f, f)
	if err != nil {
		t.Fatal(err)
	}
	in := `{"policy_name":"restarts","idempotency_key":"k"}`
	out := policyCall(t, s, f, "deactivate_policy", in)
	data, _ := out["data"].(map[string]any)
	if out["status"] != "ok" || data["state"] != "deactivated" || data["replay"] != false {
		t.Fatal("deactivation reply", out)
	}
	if out = policyCall(t, s, f, "deactivate_policy", in); out["data"].(map[string]any)["replay"] != true {
		t.Fatal("repeated deactivation is not a replay", out)
	}
	// A deactivated revision explains why it cannot be activated again.
	if out = policyCall(t, s, f, "activate_policy", in); out["status"] != "error" || out["data"].(map[string]any)["code"] != "PolicyDeactivated" {
		t.Fatal("reactivation refusal", out)
	}
	// Status of a deactivated policy reports it, with its last acceptance.
	f.status = value.PolicyStatus{PolicyUID: "policy-uid", DeactivatedID: "99999999-9999-4999-8999-999999999999", Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, MaxExecutions: 10, NotAfter: time.Now().Add(time.Hour)}
	if out = policyCall(t, s, f, "get_policy_status", `{"policy_name":"restarts"}`); out["status"] != "ok" || out["data"].(map[string]any)["state"] != "deactivated" || out["data"].(map[string]any)["acceptance_id"] != f.status.DeactivatedID {
		t.Fatal("deactivated status", out)
	}
	// A new DebugPolicy generation after deactivation can be activated: changed.
	f.status.Generation = 2
	if out = policyCall(t, s, f, "get_policy_status", `{"policy_name":"restarts"}`); out["data"].(map[string]any)["state"] != "changed" {
		t.Fatal("changed revision after deactivation", out)
	}
	// Without whole-pod collection rights nothing is dispatched.
	f.scopes = []string{"evidence:read"}
	if out = policyCall(t, s, f, "deactivate_policy", in); out["status"] != "error" || f.stopped != 2 {
		t.Fatal("deactivation without evidence:capture", out, f.stopped)
	}
}

// ADR-230: status names the detector and reports an exit occurrence's restart
// count or a probe occurrence's failure time; the output schema accepts both.
func TestPolicyStatusReportsDetectorAndOccurrenceKinds(t *testing.T) {
	f := &policyOperationsFixture{scopes: []string{"evidence:read"}}
	s, err := NewPolicyOperations("https://asservat.example.invalid", time.Now, func() string { return "88888888-8888-4888-8888-888888888888" }, f, f, f)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	f.status = value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: "99999999-9999-4999-8999-999999999999", Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, MaxExecutions: 10, NotAfter: time.Now().Add(time.Hour),
		Detector: &value.PolicyDetector{Kind: "probe", ProbeType: "Readiness", MinimumFailures: 2, WindowSeconds: 60},
		Recent: []value.PolicyOccurrenceStatus{
			{ID: "11111111-1111-4111-8111-111111111111", Outcome: "captured", CaptureID: "22222222-2222-4222-8222-222222222222", Detector: "probe", Restarts: created.Add(-time.Minute).Unix(), CreatedAt: created},
			{ID: "33333333-3333-4333-8333-333333333333", Outcome: "refused", Detector: "exit", Restarts: 3, CreatedAt: created},
		}}
	out := policyCall(t, s, f, "get_policy_status", `{"policy_name":"probes"}`)
	data, _ := out["data"].(map[string]any)
	if out["status"] != "ok" {
		t.Fatal("status", out)
	}
	detector, _ := data["detector"].(map[string]any)
	recent, _ := data["recent"].([]any)
	if detector["kind"] != "probe" || detector["probe_type"] != "Readiness" || detector["window_seconds"] != float64(60) || len(recent) != 2 {
		t.Fatal("detector", data)
	}
	probe, exit := recent[0].(map[string]any), recent[1].(map[string]any)
	if probe["detector"] != "probe" || probe["failed_at"] != "2026-10-26T11:59:00Z" || probe["restarts"] != nil || exit["detector"] != "exit" || exit["restarts"] != float64(3) || exit["failed_at"] != nil {
		t.Fatal("occurrence kinds", recent)
	}
}
