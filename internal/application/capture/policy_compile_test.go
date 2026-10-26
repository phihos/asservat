package capture

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

var testRecipe = artifact.Digest{7}

func restartSpec() map[string]any {
	return map[string]any{
		"target":    map[string]any{"cluster": "11111111-1111-4111-8111-111111111111", "namespace": "apps", "workloadRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": "api"}, "maxPods": 1, "selection": "triggeringPod", "adoption": "pinUID"},
		"detectors": []any{map[string]any{"id": "crash", "kind": "exit", "options": map[string]any{"reasons": []any{"OOMKilled", "Error"}, "exitCodes": []any{137, 1}}}},
		"when":      map[string]any{"detector": "crash"},
		"recipeRef": map[string]any{"name": "builtin-pod-status-v1", "digest": hex.EncodeToString(testRecipe[:])},
		"budgets":   map[string]any{"cooldown": "5m", "burst": 2, "maxOccurrencesPerHour": 12, "maxConcurrentActions": 1},
		"retention": "72h", "suspended": false,
		"observation": map[string]any{"mode": "allAuthorized"},
		"evaluation":  map[string]any{"scope": "pod", "fireOnActivation": false, "rearmFor": "10s"},
	}
}

func compileSpec(t *testing.T, s map[string]any) (value.RestartPolicy, error) {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return CompileRestartPolicy(b, "builtin-pod-status-v1", testRecipe)
}

func TestRestartPolicyCompilesTheAcceptedSubset(t *testing.T) {
	p, err := compileSpec(t, restartSpec())
	if err != nil || !p.Valid() {
		t.Fatal(err)
	}
	if p.WorkloadKind != "Deployment" || p.WorkloadName != "api" || strings.Join(p.Reasons, ",") != "Error,OOMKilled" || len(p.ExitCodes) != 2 || p.ExitCodes[0] != 1 || p.Interval != 5*time.Minute || p.Burst != 2 || p.RetentionSeconds != 72*3600 || p.ObservedPods != targets.MaxRestartPods {
		t.Fatalf("compiled %+v", p)
	}
	// A stricter hourly bound tightens the policy's own interval.
	s := restartSpec()
	s["budgets"].(map[string]any)["cooldown"] = "1m"
	s["budgets"].(map[string]any)["maxOccurrencesPerHour"] = 4
	if p, err = compileSpec(t, s); err != nil || p.Interval != 15*time.Minute {
		t.Fatal("hourly bound not applied", p.Interval, err)
	}
}

func TestRestartPolicyRejectsUnsupportedFieldsWithPath(t *testing.T) {
	for _, c := range []struct {
		path   string
		change func(map[string]any)
	}{
		{"spec.detectors[0].kind", func(s map[string]any) {
			s["detectors"] = []any{map[string]any{"id": "crash", "kind": "log", "options": map[string]any{"stream": "stderr", "pattern": "panic", "match": "literal"}}}
		}},
		{"spec.detectors[0].kind", func(s map[string]any) {
			s["detectors"] = []any{map[string]any{"id": "crash", "kind": "resource", "options": map[string]any{"metric": "memoryLimitRatio", "operator": "gte", "threshold": 0.9, "sampleInterval": "5s"}}}
		}},
		{"spec.detectors[0].kind", func(s map[string]any) {
			s["detectors"] = []any{map[string]any{"id": "crash", "kind": "probe", "options": map[string]any{"probeType": "Liveness", "minimumFailures": 1, "window": "30s", "source": "auto"}}}
		}},
		{"spec.detectors[1]", func(s map[string]any) {
			s["detectors"] = append(s["detectors"].([]any), map[string]any{"id": "other", "kind": "exit", "options": map[string]any{}})
		}},
		{"spec.detectors[0].options.signals", func(s map[string]any) {
			s["detectors"].([]any)[0].(map[string]any)["options"].(map[string]any)["signals"] = []any{9}
		}},
		{"spec.detectors[0].options.reasons[0]", func(s map[string]any) {
			s["detectors"].([]any)[0].(map[string]any)["options"].(map[string]any)["reasons"] = []any{"Completed"}
		}},
		{"spec.detectors[0].eventWindow", func(s map[string]any) { s["detectors"].([]any)[0].(map[string]any)["eventWindow"] = "30s" }},
		{"spec.when", func(s map[string]any) { s["when"] = map[string]any{"any": []any{map[string]any{"detector": "crash"}}} }},
		{"spec.when.detector", func(s map[string]any) { s["when"] = map[string]any{"detector": "other"} }},
		{"spec.target.cluster", func(s map[string]any) { delete(s["target"].(map[string]any), "cluster") }},
		{"spec.target.podSelector", func(s map[string]any) {
			s["target"].(map[string]any)["podSelector"] = map[string]any{"matchLabels": map[string]any{"a": "b"}}
		}},
		{"spec.target.maxPods", func(s map[string]any) { s["target"].(map[string]any)["maxPods"] = 2 }},
		{"spec.target.selection", func(s map[string]any) { s["target"].(map[string]any)["selection"] = "newest" }},
		{"spec.target.workloadRef.uid", func(s map[string]any) { s["target"].(map[string]any)["workloadRef"].(map[string]any)["uid"] = "x" }},
		{"spec.recipeRef.name", func(s map[string]any) { s["recipeRef"].(map[string]any)["name"] = "incident-context" }},
		{"spec.recipeRef.digest", func(s map[string]any) {
			s["recipeRef"].(map[string]any)["digest"] = strings.Repeat("0", 64)
		}},
		{"spec.evaluation.fireOnActivation", func(s map[string]any) { s["evaluation"].(map[string]any)["fireOnActivation"] = true }},
		{"spec.evaluation.scope", func(s map[string]any) { s["evaluation"].(map[string]any)["scope"] = "workload" }},
		{"spec.sharing", func(s map[string]any) { s["sharing"] = map[string]any{} }},
		{"spec.grantRef", func(s map[string]any) { s["grantRef"] = "22222222-2222-4222-8222-222222222222" }},
		{"spec.recordingSaves", func(s map[string]any) { s["recordingSaves"] = map[string]any{"enabled": true} }},
		{"spec.profileComposition", func(s map[string]any) { delete(s, "recipeRef"); s["profileComposition"] = map[string]any{} }},
		{"spec.observation.maxPods", func(s map[string]any) { s["observation"].(map[string]any)["maxPods"] = 1000 }},
	} {
		t.Run(c.path, func(t *testing.T) {
			s := restartSpec()
			c.change(s)
			_, err := compileSpec(t, s)
			var field value.PolicyFieldError
			if !errors.As(err, &field) || field.Path != c.path || !errors.Is(err, value.ErrInvalid) {
				t.Fatalf("got %v, want rejection at %s", err, c.path)
			}
		})
	}
}
