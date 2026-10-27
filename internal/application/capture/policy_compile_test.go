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

// probeOptions replaces the spec's detector with a valid probe detector and
// returns its options for a test to change.
func probeOptions(s map[string]any) map[string]any {
	options := map[string]any{"probeType": "Readiness", "minimumFailures": 2, "window": "1m", "source": "auto"}
	s["detectors"] = []any{map[string]any{"id": "crash", "kind": "probe", "options": options}}
	return options
}

func TestProbePolicyCompiles(t *testing.T) {
	s := restartSpec()
	probeOptions(s)
	p, err := compileSpec(t, s)
	if err != nil || !p.Valid() || p.Kind() != value.DetectorProbe || p.ProbeType != "Readiness" || p.MinimumFailures != 2 || p.ProbeWindow != time.Minute || p.Reasons != nil || p.ExitCodes != nil {
		t.Fatalf("compiled %+v %v", p, err)
	}
	// An exit policy's compiled JSON (its scope digest input) has no probe fields.
	exit, err := compileSpec(t, restartSpec())
	b, _ := json.Marshal(exit)
	if err != nil || exit.Kind() != value.DetectorExit || strings.Contains(string(b), "Probe") || strings.Contains(string(b), "Detector") {
		t.Fatal("exit policy JSON changed", string(b), err)
	}
	spec, _ := json.Marshal(s)
	if d, ok := DescribePolicyDetector(spec); !ok || d.Kind != "probe" || d.ProbeType != "Readiness" || d.MinimumFailures != 2 || d.WindowSeconds != 60 {
		t.Fatal("probe description", d, ok)
	}
	spec, _ = json.Marshal(restartSpec())
	if d, ok := DescribePolicyDetector(spec); !ok || d.Kind != "exit" || strings.Join(d.Reasons, ",") != "Error,OOMKilled" {
		t.Fatal("exit description", d, ok)
	}
}

func TestRestartPolicyRejectsUnsupportedFieldsWithPath(t *testing.T) {
	for _, c := range []struct {
		path   string
		change func(map[string]any)
	}{
		// ADR-241: log and resource detectors compile; their unsupported
		// options are rejected with their own paths.
		{"spec.detectors[0].options.stream", func(s map[string]any) {
			s["detectors"] = []any{map[string]any{"id": "crash", "kind": "log", "options": map[string]any{"stream": "stderr", "pattern": "panic", "match": "literal"}}}
		}},
		{"spec.detectors[0].options.sampleInterval", func(s map[string]any) {
			s["detectors"] = []any{map[string]any{"id": "crash", "kind": "resource", "options": map[string]any{"metric": "memoryLimitRatio", "operator": "gte", "threshold": 0.9, "sampleInterval": "5s"}}}
		}},

		{"spec.detectors[0].kind", func(s map[string]any) {
			s["detectors"] = []any{map[string]any{"id": "crash", "kind": "schedule", "options": map[string]any{"cron": "* * * * *", "timeZone": "Etc/UTC", "jitter": "0s"}}}
		}},
		{"spec.detectors[0].options.source", func(s map[string]any) { probeOptions(s)["source"] = "kubeletMetrics" }},
		{"spec.detectors[0].options.window", func(s map[string]any) { probeOptions(s)["window"] = "15s" }},
		{"spec.detectors[0].options.window", func(s map[string]any) { probeOptions(s)["window"] = "10m" }},
		{"spec.detectors[0].options.window", func(s map[string]any) { probeOptions(s)["window"] = "45500ms" }},
		{"spec.detectors[0].options.minimumFailures", func(s map[string]any) { probeOptions(s)["minimumFailures"] = 0 }},
		{"spec.detectors[0].options.probeType", func(s map[string]any) { probeOptions(s)["probeType"] = "readiness" }},
		{"spec.evaluation.rearmFor", func(s map[string]any) {
			probeOptions(s)
			s["evaluation"].(map[string]any)["rearmFor"] = "2m"
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
		{"spec.sharing.recipients", func(s map[string]any) { s["sharing"] = map[string]any{} }},
		{"spec.sharing.futureCaptures.maxCaptures", func(s map[string]any) {
			sharingSpec(s)["futureCaptures"] = map[string]any{"enabled": true, "maxCaptures": 101}
		}},
		{"spec.sharing.futureCaptures.maxCaptures", func(s map[string]any) {
			sharingSpec(s)["futureCaptures"] = map[string]any{"enabled": true, "maxCaptures": 0}
		}},
		{"spec.sharing.notAfter", func(s map[string]any) { sharingSpec(s)["notAfter"] = "tomorrow" }},
		{"spec.sharing.recipients", func(s map[string]any) {
			var r []any
			for i := 0; i < 9; i++ {
				r = append(r, map[string]any{"kind": "User", "issuer": "https://id.example.invalid", "id": strings.Repeat("u", i+1)})
			}
			sharingSpec(s)["recipients"] = r
		}},
		{"spec.sharing.recipients[1].issuer", func(s map[string]any) {
			sharingSpec(s)["recipients"] = []any{map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": "a"}, map[string]any{"kind": "Group", "issuer": "https://other.example.invalid", "id": "b"}}
		}},
		{"spec.sharing.recipients[1]", func(s map[string]any) {
			sharingSpec(s)["recipients"] = []any{map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": "a"}, map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": "a"}}
		}},
		{"spec.sharing.management", func(s map[string]any) { sharingSpec(s)["management"] = map[string]any{"mode": "personal"} }},
		{"spec.sharing.outputSelection", func(s map[string]any) { sharingSpec(s)["outputSelection"] = map[string]any{"mode": "approvedExtracts"} }},
		{"spec.sharing.reason", func(s map[string]any) { sharingSpec(s)["reason"] = "incident" }},
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

// sharingSpec adds a valid ADR-239 spec.sharing block and returns it.
func sharingSpec(s map[string]any) map[string]any {
	sharing := map[string]any{
		"recipients":     []any{map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": "incident-response"}},
		"futureCaptures": map[string]any{"enabled": true, "maxCaptures": 10},
		"notAfter":       "2026-10-30T18:00:00Z",
	}
	s["sharing"] = sharing
	return sharing
}

func TestPolicySharingCompilesShapeOnly(t *testing.T) {
	s := restartSpec()
	sharingSpec(s)
	p, err := compileSpec(t, s)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 10, 30, 18, 0, 0, 0, time.UTC)
	if p.Sharing == nil || p.Sharing.MaxCaptures != 10 || !p.Sharing.NotAfter.Equal(want) || len(p.Sharing.Recipients) != 1 || p.Sharing.Recipients[0].Kind != "Group" || p.Sharing.Recipients[0].ID != "incident-response" {
		t.Fatalf("compiled sharing %+v", p.Sharing)
	}
	// An end in the past still compiles: a running policy's poll never fails
	// on it; activation refuses it and the counter claim stops at it.
	sharingSpec(s)["notAfter"] = "2001-01-01T00:00:00Z"
	if _, err := compileSpec(t, s); err != nil {
		t.Fatal("past end refused by the compiler", err)
	}
	// Sharing changes the compiled policy, so the scope digest of an otherwise
	// equal policy differs; without sharing the digest input is unchanged.
	plain, err := compileSpec(t, restartSpec())
	if err != nil || plain.Sharing != nil {
		t.Fatal(err, plain.Sharing)
	}
	b, _ := json.Marshal(plain)
	if strings.Contains(string(b), "Sharing") {
		t.Fatal("a policy without sharing serializes a sharing field", string(b))
	}
}
