package capture

import (
	"encoding/json"
	"testing"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/conversion"
)

func ongoingSaveCompiler(raw json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
	var wire contracts.CaptureComposition
	if err := json.Unmarshal(raw, &wire); err != nil {
		return planvalue.PolicyRecorderConfiguration{}, err
	}
	c, err := conversion.CompositionFromWire(wire)
	if err != nil {
		return planvalue.PolicyRecorderConfiguration{}, err
	}
	return compiler.CompileOngoingPolicyRecorder(*c, &stubFilters{})
}

func TestPolicyRecordingSaveOptInIsExplicitReviewedCollectionIntent(t *testing.T) {
	spec := recorderPolicySpec()
	spec["profileComposition"].(map[string]any)["components"].([]any)[0].(map[string]any)["overrides"] = []any{}
	raw, _ := json.Marshal(spec)
	ordinary, err := CompilePolicyWithRecorders(raw, "builtin-pod-status-v1", testRecipe, ongoingSaveCompiler)
	if err != nil {
		t.Fatal("ongoing baseline", err)
	}
	spec["recordingSaves"] = map[string]any{"enabled": true}
	raw, _ = json.Marshal(spec)
	enabled, err := CompilePolicyWithRecorders(raw, "builtin-pod-status-v1", testRecipe, ongoingSaveCompiler)
	if err != nil {
		t.Fatal("explicit reviewed save opt-in refused for existing ongoing recorder", err)
	}
	delegation := identity.Revision{UID: "binding", Generation: 1, Digest: artifact.Digest{1}}
	before := RecorderPolicyScopeDigest("policy", 1, artifact.Digest{2}, ordinary, "namespace", "workload", delegation, nil, []string{"packetCapture"}, authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 1 << 20, MaxObservedBytes: 1 << 20})
	after := RecorderPolicyScopeDigest("policy", 1, artifact.Digest{2}, enabled, "namespace", "workload", delegation, nil, []string{"packetCapture"}, authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 1 << 20, MaxObservedBytes: 1 << 20})
	if before == (artifact.Digest{}) || after == (artifact.Digest{}) || before == after {
		t.Fatal("manual save authority not part of reviewed execution identity")
	}
}
