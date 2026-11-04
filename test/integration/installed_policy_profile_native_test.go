package integration

import (
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
	"encoding/json"
	"errors"
	"testing"
)

const installedPolicyProfileName = "regional-finite-go-profile"
const installedPolicyProfileLimit = int64(16 << 20)

func installedPolicyProfileSpec(cluster, namespace, workload string) map[string]any {
	spec := installedPolicyRecordingSpec(cluster, namespace, workload)
	spec["profileComposition"] = manualProfileArguments(cluster, namespace, workload)["profile_composition"]
	return spec
}

func installedPolicyProfileBinding(original map[string]any) map[string]any {
	binding := installedPolicyArgumentsBinding(original)
	binding["metadata"].(map[string]any)["name"] = "policy-profile-automation"
	spec := binding["spec"].(map[string]any)
	spec["reason"] = "finite installed policy profile qualification"
	spec["automation"] = map[string]any{"allowedActions": []any{"profile"}, "maxLifetimeSeconds": 3600, "maxExecutions": 1, "maxBytes": installedPolicyProfileLimit, "maxObservedBytes": 0}
	return binding
}

func installedPolicyProfileGrantInput(policyUID string) map[string]any {
	return map[string]any{"policy_name": installedPolicyProfileName, "policy_uid": policyUID, "idempotency_key": "native-policy-profile-collection", "lifetime_seconds": 600,
		"limits": map[string]any{"max_executions": 1, "max_collected_bytes": installedPolicyProfileLimit, "max_observed_bytes": 0}}
}

func installedPolicyProfileRawInput(caseID, digest string, nativeBytes int64) map[string]any {
	return map[string]any{"case_id": caseID, "artifact_digests": []string{digest}, "operations": []string{"download_artifact"}, "reason": "Inspect the synthetic policy CPU profile locally.", "max_bytes": nativeBytes, "expires_in_seconds": 300, "idempotency_key": "native-policy-profile-raw"}
}

// The same reviewed wire fields are checked before any collection approval.
type installedPolicyProfileReview struct {
	Runtime          string `json:"runtime"`
	Type             string `json:"type"`
	Mode             string `json:"mode"`
	Duration         string `json:"duration"`
	Timeout          string `json:"timeout"`
	ForceGC          bool   `json:"force_gc"`
	SourceRef        string `json:"source_ref"`
	SourceName       string `json:"source_name"`
	SourceKind       string `json:"source_kind"`
	AddressMode      string `json:"address_mode"`
	DefinitionDigest string `json:"definition_digest"`
	DeclaredPortName string `json:"declared_port_name"`
	MinimumPort      uint16 `json:"minimum_port"`
	MaximumPort      uint16 `json:"maximum_port"`
	Port             uint16 `json:"port"`
	EndpointDigest   string `json:"endpoint_digest"`
}

func installedPolicyProfileExpectedBinding(t testing.TB, authored map[string]any) targets.ProfileEndpointBinding {
	t.Helper()
	raw, err := json.Marshal(authored["profileComposition"])
	var wire contracts.CaptureComposition
	if err != nil || json.Unmarshal(raw, &wire) != nil {
		t.Fatal("authored policy profile composition", err)
	}
	composition, err := conversion.CompositionFromWire(wire)
	if err != nil || composition == nil {
		t.Fatal("authored policy profile conversion", err)
	}
	_, err = compiler.CompilePolicyRecorder(*composition, nil)
	var needed compiler.PolicyProfileEndpointNeeded
	if !errors.As(err, &needed) || len(needed.Bindings) != 1 || needed.SourceRef != needed.Bindings[0].Name || !needed.Bindings[0].Valid() {
		t.Fatal("authored policy profile normalized binding", err)
	}
	return needed.Bindings[0]
}

func installedPolicyProfileReviewMatches(p installedPolicyProfileReview, b targets.ProfileEndpointBinding) bool {
	return p.Runtime == "go" && p.Type == "cpu" && p.Mode == "interval" && p.Duration == "10s" && p.Timeout == "15s" && !p.ForceGC && p.SourceRef == b.Name && p.SourceName == b.TemplateRef && p.AddressMode == b.AddressMode && p.SourceKind == "templateBinding" && len(p.DefinitionDigest) == 64 && p.DeclaredPortName == b.PortName && p.MinimumPort == 6060 && p.MaximumPort == 6060 && p.Port == 0 && p.EndpointDigest == ""
}
