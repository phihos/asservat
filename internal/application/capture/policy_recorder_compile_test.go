package capture

import (
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/conversion"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	value "asservat.local/asservat/internal/domain/capture"
	planningvalue "asservat.local/asservat/internal/domain/planning"
)

func recorderPolicySpec() map[string]any {
	s := restartSpec()
	delete(s, "recipeRef")
	s["profileComposition"] = map[string]any{"components": []any{map[string]any{"id": "net", "profileRef": map[string]any{"catalog": "builtin", "name": "network-connections", "version": "v1"}, "overrides": []any{
		map[string]any{"actionID": "sample", "field": "actionExecutionMode", "value": "onTrigger"},
		map[string]any{"actionID": "sample", "field": "packetBefore", "value": "0s"},
		map[string]any{"actionID": "sample", "field": "packetAfter", "value": "2s"},
		map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "10s"},
	}}}, "maxTotalBytes": 16 << 20, "maxDuration": "20s"}
	return s
}

func TestPolicyCompilesFiniteRecorderConfigurationWithoutPodOrCapture(t *testing.T) {
	s := recorderPolicySpec()
	s["grantRef"] = "00000000-0000-4000-8000-000000000001"
	b, _ := json.Marshal(s)
	p, err := CompilePolicyWithRecorders(b, "builtin-pod-status-v1", testRecipe, testPolicyRecorderCompiler)
	if err != nil || !p.Valid() || p.Recorder == nil || p.GrantRef != s["grantRef"] {
		t.Fatal(p, err)
	}
	if p.Recorder.Action.ExecutionMode != "onTrigger" || p.Recorder.Action.Before != "0s" {
		t.Fatal("ongoing source accidentally armed")
	}
	var frozen map[string]any
	raw, _ := json.Marshal(p)
	if json.Unmarshal(raw, &frozen) != nil {
		t.Fatal("compiled policy")
	}
	if _, ok := frozen["GrantRef"]; ok {
		t.Fatal("grant pointer participates in collection identity")
	}
	if _, err = CompileRestartPolicy(b, "builtin-pod-status-v1", testRecipe); err == nil {
		t.Fatal("legacy unavailable path widened")
	}
}

func TestPolicyRecorderRejectsUnsupportedLifecycleAndAmbiguousSelection(t *testing.T) {
	s := recorderPolicySpec()
	composition := s["profileComposition"].(map[string]any)
	component := composition["components"].([]any)[0].(map[string]any)
	component["overrides"] = []any{}
	b, _ := json.Marshal(s)
	_, err := CompilePolicyWithRecorders(b, "builtin-pod-status-v1", testRecipe, testPolicyRecorderCompiler)
	var c planningvalue.CompositionError
	if !errors.As(err, &c) || c.Code != planningvalue.CompositionRecorderUnavailable {
		t.Fatal("ongoing source accepted", err)
	}
	s = recorderPolicySpec()
	s["recipeRef"] = restartSpec()["recipeRef"]
	b, _ = json.Marshal(s)
	_, err = CompilePolicyWithRecorders(b, "builtin-pod-status-v1", testRecipe, testPolicyRecorderCompiler)
	var field value.PolicyFieldError
	if !errors.As(err, &field) || field.Path != "spec.recipeRef" {
		t.Fatal("ambiguous recipe selection", err)
	}
}

func testPolicyRecorderCompiler(raw json.RawMessage) (planningvalue.PolicyRecorderConfiguration, error) {
	var wire contracts.CaptureComposition
	if err := json.Unmarshal(raw, &wire); err != nil {
		return planningvalue.PolicyRecorderConfiguration{}, err
	}
	composition, err := conversion.CompositionFromWire(wire)
	if err != nil {
		return planningvalue.PolicyRecorderConfiguration{}, err
	}
	return compiler.CompilePolicyRecorder(*composition, &stubFilters{})
}

func TestRecorderPolicyScopeControlEditsDoNotReissueAuthority(t *testing.T) {
	s := recorderPolicySpec()
	raw, _ := json.Marshal(s)
	p, err := CompilePolicyWithRecorders(raw, "builtin-pod-status-v1", testRecipe, testPolicyRecorderCompiler)
	if err != nil {
		t.Fatal(err)
	}
	collection := artifact.Digest{1}
	delegation := identity.Revision{UID: "binding", Generation: 1, Digest: artifact.Digest{2}}
	scope := func(p value.RestartPolicy, version int64, bytes int64) artifact.Digest {
		return RecorderPolicyScopeDigest("policy-uid", version, collection, p, "namespace-uid", "workload-uid", delegation, nil, []string{"packetCapture"}, authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: bytes, MaxObservedBytes: 1 << 20})
	}
	first := scope(p, 1, 1<<20)
	if first == (artifact.Digest{}) {
		t.Fatal("empty scope")
	}
	p.GrantRef = "00000000-0000-4000-8000-000000000001"
	if scope(p, 1, 1<<20) != first {
		t.Fatal("grant attachment reissued authority")
	}
	p.GrantRef = "00000000-0000-4000-8000-000000000002"
	if scope(p, 1, 1<<20) != first {
		t.Fatal("renewal grant refilled policy scope")
	}
	if scope(p, 3, 1<<20) == first {
		t.Fatal("observed collection ABA reused prior approval")
	}
	if scope(p, 1, 2<<20) == first {
		t.Fatal("changed delegated budget reused prior approval")
	}
}

func TestRecorderPolicyScopeRefusesUnreviewableConfigurationExpansion(t *testing.T) {
	raw, _ := json.Marshal(recorderPolicySpec())
	p, err := CompilePolicyWithRecorders(raw, "builtin-pod-status-v1", testRecipe, testPolicyRecorderCompiler)
	if err != nil {
		t.Fatal(err)
	}
	delegation := identity.Revision{UID: "binding", Generation: 1, Digest: artifact.Digest{2}}
	scope := func() []byte {
		return RecorderPolicyScope("policy-uid", 1, artifact.Digest{1}, p, "namespace-uid", "workload-uid", delegation, nil, []string{"packetCapture"}, authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 1 << 20, MaxObservedBytes: 1 << 20})
	}
	if b := scope(); len(b) == 0 {
		t.Fatal("ordinary reviewed scope refused")
	}
	// The inert configuration permits up to 64 KiB. Its enclosing acceptance
	// includes other authority fields and JSON/base64 expansion, so that nested
	// bound alone cannot guarantee the resulting grant remains reviewable.
	p.Recorder.Scope = bytes.Repeat([]byte{' '}, authorization.GrantMaxScopeBytes)
	if !p.Valid() {
		t.Fatal("configuration fixture outside its existing size bound")
	}
	if b := scope(); b != nil {
		t.Fatal("accepted scope exceeds existing grant review limit", len(b))
	}
	if d := RecorderPolicyScopeDigest("policy-uid", 1, artifact.Digest{1}, p, "namespace-uid", "workload-uid", delegation, nil, []string{"packetCapture"}, authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 1 << 20, MaxObservedBytes: 1 << 20}); d != (artifact.Digest{}) {
		t.Fatal("oversized scope obtained an acceptance digest")
	}
}

func TestRecorderPolicyUnsharedScopeDigestBaseline(t *testing.T) {
	raw, _ := json.Marshal(recorderPolicySpec())
	p, err := CompilePolicyWithRecorders(raw, "builtin-pod-status-v1", testRecipe, testPolicyRecorderCompiler)
	if err != nil {
		t.Fatal(err)
	}
	got := RecorderPolicyScopeDigest("policy-uid", 1, artifact.Digest{1}, p, "namespace-uid", "workload-uid", identity.Revision{UID: "binding", Generation: 1, Digest: artifact.Digest{2}}, nil, []string{"packetCapture"}, authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 1 << 20, MaxObservedBytes: 1 << 20})
	// Captured with the original fc02 serializer through a Go source overlay.
	// This scope has no sharing; control exclusion must preserve its exact bytes.
	const want = "d473410e70800be5d8b93c1f201d0fecd7c323df859c60ee82de1c9cb0090aba"
	if fmt.Sprintf("%x", got) != want {
		t.Fatalf("unshared recorder collection digest changed: got %x want %s", got, want)
	}
}
