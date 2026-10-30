package capture

import (
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func TestRecordingSaveIncidentPodCapIsReviewedIndependentlyOfObservation(t *testing.T) {
	spec := recorderPolicySpec()
	spec["profileComposition"].(map[string]any)["components"].([]any)[0].(map[string]any)["overrides"] = []any{}
	spec["recordingSaves"] = map[string]any{"enabled": true}
	compile := func(cap int) (artifact.Digest, int) {
		t.Helper()
		spec["target"].(map[string]any)["maxPods"] = cap
		raw, _ := json.Marshal(spec)
		p, err := CompilePolicyWithRecorders(raw, "builtin-pod-status-v1", testRecipe, ongoingSaveCompiler)
		if err != nil {
			t.Fatal("valid ongoing manual Save incident cap", cap, err)
		}
		if p.ObservedPods <= cap {
			t.Fatal("incident cap shrank source observation cohort", p.ObservedPods, cap)
		}
		digest := RecorderPolicyScopeDigest("policy", 1, artifact.Digest{2}, p, "namespace", "workload", identity.Revision{UID: "binding", Generation: 1, Digest: artifact.Digest{1}}, nil, []string{"packetCapture"}, authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 1 << 30, MaxObservedBytes: 1 << 30})
		return digest, recordingSaveIncidentPodCap(p)
	}
	one, capOne := compile(1)
	two, capTwo := compile(2)
	if capOne != 1 || capTwo != 2 || one == two {
		t.Fatal("incident cap absent from effective bound or reviewed scope", capOne, capTwo)
	}
	_, capSixteen := compile(16)
	if capSixteen != 16 {
		t.Fatal("group cannot use authored16Pod cap", capSixteen)
	}
}
