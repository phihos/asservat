package integration

import (
	"asservat.local/asservat/internal/contracts"
	"encoding/json"
	"strings"
	"testing"
)

func TestInstalledPolicyProfileProtectedInputs(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	binding := installedPolicyProfileBinding(map[string]any{"subjects": []any{map[string]any{"kind": "Group", "issuer": "https://id.example.test", "id": "fixture-team"}}, "scope": map[string]any{"clusterID": id, "namespaceRef": map[string]any{"name": "payments", "uid": "namespace"}, "workloads": []any{map[string]any{"kind": "Deployment", "name": "api", "uid": "workload"}}}})
	validateInstalledPolicyProtectedInputs(t, installedPolicyProfileSpec(id, "payments", "api"), binding)
	limits := installedPolicyProfileGrantInput(id)["limits"].(map[string]any)
	if limits["max_observed_bytes"] != 0 {
		t.Fatal("profile observation allowance must be explicit zero")
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for op, input := range map[string]any{"request_policy_grant": installedPolicyProfileGrantInput(id), "request_raw_access": installedPolicyProfileRawInput(id, strings.Repeat("a", 64), 4096)} {
		raw, _ := json.Marshal(input)
		if err := wire.ValidateInput(op, raw); err != nil {
			t.Fatal(op, err)
		}
		if strings.Contains(string(raw), "observation_limits") || strings.Contains(string(raw), "max_observed_events") {
			t.Fatal("profile invented observation allowance")
		}
	}
}

func TestInstalledPolicyProfileReviewUsesNormalizedBinding(t *testing.T) {
	binding := installedPolicyProfileExpectedBinding(t, installedPolicyProfileSpec("11111111-1111-4111-8111-111111111111", "payments", "api"))
	// Model the actual public review's normalized source identity. Other facts
	// are the fixture's fixed operator definition and builtin CPU parameters.
	review := installedPolicyProfileReview{Runtime: "go", Type: "cpu", Mode: "interval", Duration: "10s", Timeout: "15s", SourceRef: binding.Name, SourceName: binding.TemplateRef, SourceKind: "templateBinding", AddressMode: binding.AddressMode, DefinitionDigest: strings.Repeat("a", 64), DeclaredPortName: binding.PortName, MinimumPort: 6060, MaximumPort: 6060}
	if !installedPolicyProfileReviewMatches(review, binding) {
		t.Fatal("actual composed binding rejected by installed review assertion", binding.Name)
	}
	wrong := review
	wrong.SourceRef = "api-local-pprof"
	if installedPolicyProfileReviewMatches(wrong, binding) {
		t.Fatal("unscoped authored alias accepted as concrete composed binding")
	}
}
