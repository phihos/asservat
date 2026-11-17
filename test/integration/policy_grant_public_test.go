package integration

import (
	"context"
	"encoding/json"
	"testing"

	captureapp "asservat.local/asservat/internal/application/capture"
	planningapp "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
)

type publicPolicyIdentity struct{ i identity.Identity }

func (s *publicPolicyIdentity) ResolveIdentity(context.Context) (identity.Identity, error) {
	return s.i, nil
}

// The pinned corpus is genuine libpcap output for exactly this expression.
// Refuse other expressions rather than impersonating a general filter compiler.
type publicPolicyFilters struct{}

func (publicPolicyFilters) CompileFilter(expression string) (planvalue.CompiledFilter, error) {
	if expression != "tcp dst port 80" {
		return planvalue.CompiledFilter{}, planvalue.ErrInvalid
	}
	return (recordingCompiler{}).CompileFilter(expression)
}

var publicPolicyCompile = captureapp.SingleRecorder(publicPolicyCompileOne)

func publicPolicyCompileOne(raw json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
	var wire contracts.CaptureComposition
	if err := json.Unmarshal(raw, &wire); err != nil {
		return planvalue.PolicyRecorderConfiguration{}, err
	}
	composition, err := conversion.CompositionFromWire(wire)
	if err != nil || composition == nil {
		return planvalue.PolicyRecorderConfiguration{}, planvalue.ErrInvalid
	}
	return planningapp.CompilePolicyRecorder(*composition, publicPolicyFilters{})
}
func publicPolicySpec(t testing.TB, a authorization.AcceptedPolicyAuthority) []byte {
	t.Helper()
	spec := map[string]any{
		"target":    map[string]any{"cluster": a.ClusterID, "namespace": "app", "workloadRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": "app"}, "maxPods": 1, "selection": "triggeringPod", "adoption": "pinUID"},
		"detectors": []any{map[string]any{"id": "crash", "kind": "exit", "options": map[string]any{"reasons": []any{"OOMKilled", "Error"}, "exitCodes": []any{137, 1}}}},
		"when":      map[string]any{"detector": "crash"},
		"budgets":   map[string]any{"cooldown": "5m", "burst": 2, "maxOccurrencesPerHour": 12, "maxConcurrentActions": 1},
		"retention": "1h", "suspended": false, "observation": map[string]any{"mode": "allAuthorized"}, "evaluation": map[string]any{"scope": "pod", "fireOnActivation": false, "rearmFor": "10s"},
		"profileComposition": map[string]any{"components": []any{map[string]any{"id": "net", "profileRef": map[string]any{"catalog": "builtin", "name": "network-connections", "version": "v1"}, "overrides": []any{
			map[string]any{"actionID": "sample", "field": "actionExecutionMode", "value": "onTrigger"},
			map[string]any{"actionID": "sample", "field": "packetBefore", "value": "0s"},
			map[string]any{"actionID": "sample", "field": "packetAfter", "value": "1s"},
			map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "10s"},
			map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp dst port 80"},
		}}}, "maxTotalBytes": 16 << 20, "maxDuration": "10s"},
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPublicPolicyGrantFixtureUsesSupportedCompilerInputs(t *testing.T) {
	spec := publicPolicySpec(t, authorization.AcceptedPolicyAuthority{ClusterID: "11111111-1111-4111-8111-111111111111"})
	compiled, err := captureapp.CompilePolicyWithRecorders(t.Context(), targets.Request{}, spec, planningapp.ContextRecipeName, planningapp.RecipeDigest(), publicPolicyCompile)
	if err != nil || compiled.Recorder == nil {
		t.Fatal("public fixture cannot compile actual protected configuration", err)
	}
	action := compiled.Recorder.Action
	if action.Filter != "tcp dst port 80" || action.ExecutionMode != "onTrigger" || action.Before != "0s" || action.After != "1s" || action.FilterInstructions != len(recordingProgram) {
		t.Fatal("public fixture review differs from supported compiler output", action)
	}
	if _, err := (publicPolicyFilters{}).CompileFilter("tcp port 443"); err == nil {
		t.Fatal("fixture corpus impersonated another filter")
	}
}
