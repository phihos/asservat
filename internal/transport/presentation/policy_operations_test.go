package presentation

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

const policyTestCluster = "11111111-1111-4111-8111-111111111111"

type policyOperationsFixture struct {
	scopes  []string
	stopped int
	status  value.PolicyStatus
	named   []string
}

func newPolicyOperations(t *testing.T, f *policyOperationsFixture) *PolicyOperations {
	t.Helper()
	s, err := NewPolicyOperations("https://asservat.example.invalid", time.Now, func() string { return "88888888-8888-4888-8888-888888888888" }, NewClusterNames(map[string]string{"local": policyTestCluster}), f, f)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *policyOperationsFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	now := time.Now()
	return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}, Scopes: f.scopes, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}, nil
}
func (f *policyOperationsFixture) Get(_ context.Context, _ identities.CurrentIdentity, cluster, namespace, name string) (value.PolicyStatus, time.Time, error) {
	f.named = []string{cluster, namespace, name}
	return f.status, time.Now().Add(5 * time.Second), nil
}
func (f *policyOperationsFixture) Deactivate(_ context.Context, _ identities.CurrentIdentity, cluster, namespace, name string) (app.PolicyDeactivationResult, error) {
	f.named = []string{cluster, namespace, name}
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
	s := newPolicyOperations(t, f)
	in := `{"cluster":"local","namespace":"apps","policy_name":"restarts","idempotency_key":"k"}`
	out := policyCall(t, s, f, "deactivate_policy", in)
	data, _ := out["data"].(map[string]any)
	if out["status"] != "ok" || data["state"] != "deactivated" || data["replay"] != false || data["policy_name"] != "restarts" || data["namespace"] != "apps" || !slices.Equal(f.named, []string{policyTestCluster, "apps", "restarts"}) {
		t.Fatal("deactivation reply", out, f.named)
	}
	// An unknown cluster name is a domain refusal; nothing is dispatched.
	if out = policyCall(t, s, f, "deactivate_policy", `{"cluster":"elsewhere","namespace":"apps","policy_name":"restarts","idempotency_key":"k"}`); out["status"] != "error" || out["data"].(map[string]any)["code"] != "UnknownCluster" || f.stopped != 1 {
		t.Fatal("unknown cluster", out)
	}
	if out = policyCall(t, s, f, "deactivate_policy", in); out["data"].(map[string]any)["replay"] != true {
		t.Fatal("repeated deactivation is not a replay", out)
	}
	// Status of a deactivated policy reports it, with its last acceptance.
	f.status = value.PolicyStatus{PolicyUID: "policy-uid", DeactivatedID: "99999999-9999-4999-8999-999999999999", Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, MaxExecutions: 10, NotAfter: time.Now().Add(time.Hour)}
	if out = policyCall(t, s, f, "get_policy_status", `{"cluster":"local","namespace":"apps","policy_name":"restarts"}`); out["status"] != "ok" || out["data"].(map[string]any)["state"] != "deactivated" || out["data"].(map[string]any)["acceptance_id"] != f.status.DeactivatedID {
		t.Fatal("deactivated status", out)
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
	s := newPolicyOperations(t, f)
	created := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	f.status = value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: "99999999-9999-4999-8999-999999999999", Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, MaxExecutions: 10, NotAfter: time.Now().Add(time.Hour),
		Detector: &value.PolicyDetector{Kind: "probe", ProbeType: "Readiness", MinimumFailures: 2, WindowSeconds: 60},
		Recent: []value.PolicyOccurrenceStatus{
			{ID: "11111111-1111-4111-8111-111111111111", Outcome: "captured", CaptureID: "22222222-2222-4222-8222-222222222222", Detector: "probe", Restarts: created.Add(-time.Minute).Unix(), CreatedAt: created},
			{ID: "33333333-3333-4333-8333-333333333333", Outcome: "refused", Detector: "exit", Restarts: 3, CreatedAt: created},
		}}
	out := policyCall(t, s, f, "get_policy_status", `{"cluster":"local","namespace":"apps","policy_name":"probes"}`)
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

func TestPolicyStatusReportsSharedAcceptedPoolsIndependentlyOfGrants(t *testing.T) {
	f := &policyOperationsFixture{scopes: []string{"evidence:read"}}
	f.status = value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: "99999999-9999-4999-8999-999999999999", Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, ExecutionsSpent: 5, MaxExecutions: 100, CollectedBytesSpent: 16384, MaxCollectedBytes: 1048576, ObservedBytesSpent: 4096, MaxObservedBytes: 8192, NotAfter: time.Now().Add(time.Hour)}
	s := newPolicyOperations(t, f)
	for _, expired := range []bool{false, true} {
		if expired {
			f.status.NotAfter = time.Now().Add(-time.Hour)
		}
		out := policyCall(t, s, f, "get_policy_status", `{"cluster":"local","namespace":"apps","policy_name":"restarts"}`)
		data := out["data"].(map[string]any)
		for key, expected := range map[string]int64{"executions_spent": 5, "collected_bytes_spent": 16384, "max_collected_bytes": 1048576} {
			if data[key] != float64(expected) {
				t.Fatalf("shared accepted %s = %v, want %d", key, data[key], expected)
			}
		}
		if expired && data["state"] != "expired" {
			t.Fatal("budget metadata hid original expiry", data)
		}
	}
}

func TestPolicyProfileStatusReportsNativeCollectionAndOriginalSpend(t *testing.T) {
	f := &policyOperationsFixture{scopes: []string{"evidence:read"}, status: value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: "99999999-9999-4999-8999-999999999999", AttachedGrantID: "77777777-7777-4777-8777-777777777777", Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, ExecutionsSpent: 1, MaxExecutions: 1, CollectedBytesSpent: 16 << 20, MaxCollectedBytes: 16 << 20, NotAfter: time.Now().Add(time.Hour), Authority: authorization.AcceptedPolicyAuthority{Actions: []string{"profile"}}}}
	s := newPolicyOperations(t, f)
	if tool, ok := s.Tool("get_policy_status"); !ok || !tool.MCP() || len(tool.Transports) != 0 && !slices.Contains(tool.Transports, "browser") {
		t.Fatal("profile policy status lost its shared MCP/browser contract")
	}
	out := policyCall(t, s, f, "get_policy_status", `{"cluster":"local","namespace":"apps","policy_name":"regional-finite-go-profile"}`)
	data := out["data"].(map[string]any)
	if out["status"] != "ok" || data["collection_kind"] != "profile" || data["attached_grant_id"] != f.status.AttachedGrantID || data["executions_spent"] != float64(1) || data["collected_bytes_spent"] != float64(16<<20) || data["observed_bytes_spent"] != nil || data["max_observed_bytes"] != nil {
		t.Fatal("native profile status mislabeled collection or changed original pools", data)
	}
}

func TestPolicyProfileStatusContractAcceptsProfileAndRefusesUnknownCollection(t *testing.T) {
	f := &policyOperationsFixture{scopes: []string{"evidence:read"}, status: value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: "99999999-9999-4999-8999-999999999999", Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, MaxExecutions: 1, NotAfter: time.Now().Add(time.Hour)}}
	s := newPolicyOperations(t, f)
	out := policyCall(t, s, f, "get_policy_status", `{"cluster":"local","namespace":"apps","policy_name":"regional-finite-go-profile"}`)
	for _, kind := range []string{"podStatus", "packetCapture", "syscallTrace", "profile", "unknown"} {
		out["data"].(map[string]any)["collection_kind"] = kind
		raw, _ := json.Marshal(out)
		if err := s.contracts.ValidateOutput("get_policy_status", raw); (err == nil) != (kind != "unknown") {
			t.Fatal("incorrect closed collection kind", kind, err)
		}
	}
}

func TestPolicyLogsStatusReportsNativeCollectionAndOriginalSpend(t *testing.T) {
	f := &policyOperationsFixture{scopes: []string{"evidence:read"}, status: value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: "99999999-9999-4999-8999-999999999999", Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, ExecutionsSpent: 1, MaxExecutions: 2, CollectedBytesSpent: 64 << 20, MaxCollectedBytes: 128 << 20, NotAfter: time.Now().Add(time.Hour), Authority: authorization.AcceptedPolicyAuthority{Actions: []string{"logs"}}}}
	s := newPolicyOperations(t, f)
	out := policyCall(t, s, f, "get_policy_status", `{"cluster":"local","namespace":"apps","policy_name":"finite-logs"}`)
	data := out["data"].(map[string]any)
	if data["collection_kind"] != "logs" || data["executions_spent"] != float64(1) || data["collected_bytes_spent"] != float64(64<<20) {
		t.Fatal("log policy status lost exact finite collection or spend", data)
	}
	raw, _ := json.Marshal(out)
	if s.contracts.ValidateOutput("get_policy_status", raw) != nil {
		t.Fatal("MCP/browser logs status rejected")
	}
}
