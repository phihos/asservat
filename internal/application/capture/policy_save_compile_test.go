package capture

import (
	"asservat.local/asservat/internal/domain/targets"
	"context"
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

var ongoingSaveCompiler = SingleRecorder(ongoingSaveCompilerOne)

func ongoingSaveCompilerOne(raw json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
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
	ordinary, err := CompilePolicyWithRecorders(context.Background(), targets.Request{}, raw, "builtin-pod-status-v1", testRecipe, ongoingSaveCompiler)
	if err != nil {
		t.Fatal("ongoing baseline", err)
	}
	spec["recordingSaves"] = map[string]any{"enabled": true}
	raw, _ = json.Marshal(spec)
	enabled, err := CompilePolicyWithRecorders(context.Background(), targets.Request{}, raw, "builtin-pod-status-v1", testRecipe, ongoingSaveCompiler)
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

// ADR-275: one DebugPolicy composing the packet and syscall builtins
// compiles into two ongoing recorders, both delegated action kinds, and a
// valid policy; a second packet component is an acquisition conflict.
func TestPolicyComposesPacketAndSyscallRecorders(t *testing.T) {
	recorders := func(_ context.Context, _ targets.Request, raw json.RawMessage) ([]planvalue.PolicyRecorderConfiguration, error) {
		var wire contracts.CaptureComposition
		if err := json.Unmarshal(raw, &wire); err != nil {
			return nil, err
		}
		c, err := conversion.CompositionFromWire(wire)
		if err != nil {
			return nil, err
		}
		return compiler.CompileOngoingPolicyRecorders(*c, &stubFilters{})
	}
	spec := recorderPolicySpec()
	composition := spec["profileComposition"].(map[string]any)
	network := composition["components"].([]any)[0].(map[string]any)
	network["overrides"] = []any{}
	calls := map[string]any{"id": "calls", "profileRef": map[string]any{"catalog": "builtin", "name": "syscall-activity", "version": "v1"}}
	composition["components"] = []any{network, calls}
	composition["maxTotalBytes"], composition["maxDuration"] = 32<<20, "30s"
	spec["recordingSaves"] = map[string]any{"enabled": true}
	raw, _ := json.Marshal(spec)
	p, err := CompilePolicyWithRecorders(context.Background(), targets.Request{}, raw, "builtin-pod-status-v1", testRecipe, recorders)
	if err != nil || !p.Valid() || len(p.Recorders()) != 2 || p.Recorder.Action.Kind != "packetCapture" || p.MoreRecorders[0].Action.Kind != "syscallTrace" {
		t.Fatal("mixed policy", err)
	}
	if kinds := recorderKinds(p); len(kinds) != 2 || kinds[0] != "packetCapture" || kinds[1] != "syscallTrace" {
		t.Fatal("delegated kinds", kinds)
	}
	second := map[string]any{"id": "network2", "profileRef": network["profileRef"]}
	composition["components"] = []any{network, second}
	raw, _ = json.Marshal(spec)
	if _, err = CompilePolicyWithRecorders(context.Background(), targets.Request{}, raw, "builtin-pod-status-v1", testRecipe, recorders); err == nil {
		t.Fatal("two packet recorders on the same Pods compiled")
	}
}
