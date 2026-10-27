package capture

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

// logDetector replaces the spec's detector with a valid ADR-241 log detector
// (the spec keeps rearmFor 10s) and returns the detector and its options.
func logDetector(s map[string]any) (map[string]any, map[string]any) {
	options := map[string]any{"stream": "both", "pattern": `panic: .*timeout`, "match": "regexp"}
	d := map[string]any{"id": "crash", "kind": "log", "options": options}
	s["detectors"] = []any{d}
	return d, options
}

func resourceOptions(s map[string]any) map[string]any {
	options := map[string]any{"metric": "cpuQuotaRatio", "operator": "gt", "threshold": 0.8, "sampleInterval": "60s"}
	s["detectors"] = []any{map[string]any{"id": "crash", "kind": "resource", "options": options}}
	return options
}

func TestLogPolicyCompiles(t *testing.T) {
	s := restartSpec()
	d, options := logDetector(s)
	p, err := compileSpec(t, s)
	if err != nil || !p.Valid() || p.Kind() != value.DetectorLog || p.Log == nil || !p.Log.Regexp || p.Log.WindowSeconds != 30 || p.Log.MaxRecordBytes != targets.MaxLogRecordBytes || p.Log.MatchPrefix || p.Resource != nil {
		t.Fatalf("compiled %+v %v", p, err)
	}
	if r := p.Request(); r.Log == nil || r.Log.Pattern != `panic: .*timeout` || r.Resource != nil || r.Alert || r.Probe != "" || !r.Valid() {
		t.Fatal("request", r)
	}
	// A JSON field predicate, a literal, a record bound and a longer window.
	options["match"], options["pattern"], options["jsonField"], options["maxRecordBytes"] = "literal", "connection refused", "error.message", 4096
	d["eventWindow"] = "2m"
	if p, err = compileSpec(t, s); err != nil || !p.Valid() || p.Log.Regexp || p.Log.JSONField != "error.message" || p.Log.MaxRecordBytes != 4096 || p.Log.WindowSeconds != 120 {
		t.Fatal("json literal", p, err)
	}
	delete(options, "jsonField")
	options["overlong"] = "matchPrefix"
	if p, err = compileSpec(t, s); err != nil || !p.Log.MatchPrefix {
		t.Fatal("matchPrefix", p, err)
	}
	spec, _ := json.Marshal(s)
	if d, ok := DescribePolicyDetector(spec); !ok || d.Kind != "log" || d.LogMatch != "literal" || d.WindowSeconds != 120 {
		t.Fatal("log description", d, ok)
	}
	// Other detectors' compiled JSON (their scope digest input) is unchanged.
	exit, _ := compileSpec(t, restartSpec())
	if b, _ := json.Marshal(exit); strings.Contains(string(b), "Log") || strings.Contains(string(b), "Resource") {
		t.Fatal("exit policy JSON changed", string(b))
	}
}

func TestResourcePolicyCompiles(t *testing.T) {
	s := restartSpec()
	options := resourceOptions(s)
	p, err := compileSpec(t, s)
	if err != nil || !p.Valid() || p.Kind() != value.DetectorResource || p.Resource == nil || *p.Resource != (targets.ResourceCondition{Metric: "cpuQuotaRatio", Operator: "gt", Threshold: 0.8, MaxAgeSeconds: 60}) || p.Log != nil {
		t.Fatalf("compiled %+v %v", p, err)
	}
	if r := p.Request(); r.Resource == nil || r.Log != nil || !r.Valid() {
		t.Fatal("request", r)
	}
	// Quota and memory utilization may exceed one (spec: never clamped).
	options["metric"], options["operator"], options["threshold"] = "memoryBytes", "gte", 5.0e8
	if p, err = compileSpec(t, s); err != nil || p.Resource.Threshold != 5e8 {
		t.Fatal("memoryBytes", p, err)
	}
	spec, _ := json.Marshal(s)
	if d, ok := DescribePolicyDetector(spec); !ok || d.Kind != "resource" || d.Resource == nil || d.Resource.Metric != "memoryBytes" {
		t.Fatal("resource description", d, ok)
	}
}

func TestLogAndResourcePoliciesRejectWithPath(t *testing.T) {
	for _, c := range []struct {
		path   string
		mutate func(map[string]any)
	}{
		{"spec.detectors[0].options.stream", func(s map[string]any) { _, o := logDetector(s); o["stream"] = "stdout" }},
		{"spec.detectors[0].options.match", func(s map[string]any) { _, o := logDetector(s); o["match"] = "glob" }},
		// Backreferences and look-around are not RE2.
		{"spec.detectors[0].options.pattern", func(s map[string]any) { _, o := logDetector(s); o["pattern"] = `(a)\1` }},
		{"spec.detectors[0].options.pattern", func(s map[string]any) { _, o := logDetector(s); o["pattern"] = `foo(?=bar)` }},
		// A pattern whose compiled program exceeds the bound.
		{"spec.detectors[0].options.pattern", func(s map[string]any) { _, o := logDetector(s); o["pattern"] = `(x{1,100}){1,100}` }},
		{"spec.detectors[0].options.pattern", func(s map[string]any) { _, o := logDetector(s); o["pattern"] = strings.Repeat("a", 1025) }},
		{"spec.detectors[0].options.maxRecordBytes", func(s map[string]any) { _, o := logDetector(s); o["maxRecordBytes"] = 65537 }},
		{"spec.detectors[0].options.overlong", func(s map[string]any) {
			_, o := logDetector(s)
			o["jsonField"], o["overlong"] = "msg", "matchPrefix"
		}},
		{"spec.detectors[0].options.jsonField", func(s map[string]any) { _, o := logDetector(s); o["jsonField"] = "a..b" }},
		{"spec.detectors[0].options.jsonField", func(s map[string]any) { _, o := logDetector(s); o["jsonField"] = "a.b.c.d.e.f.g.h.i" }},
		{"spec.detectors[0].eventWindow", func(s map[string]any) { d, _ := logDetector(s); d["eventWindow"] = "15s" }},
		{"spec.detectors[0].eventWindow", func(s map[string]any) { d, _ := logDetector(s); d["eventWindow"] = "6m" }},
		{"spec.evaluation.rearmFor", func(s map[string]any) {
			logDetector(s)
			s["evaluation"].(map[string]any)["rearmFor"] = "31s"
		}},
		{"spec.detectors[0].options.metric", func(s map[string]any) { resourceOptions(s)["metric"] = "cpuThrottledRatio" }},
		{"spec.detectors[0].options.metric", func(s map[string]any) { resourceOptions(s)["metric"] = "memoryPSI" }},
		{"spec.detectors[0].options.metric", func(s map[string]any) { resourceOptions(s)["metric"] = "memoryGrowthBytesPerSecond" }},
		{"spec.detectors[0].options.operator", func(s map[string]any) { resourceOptions(s)["operator"] = "eq" }},
		{"spec.detectors[0].options.threshold", func(s map[string]any) { resourceOptions(s)["threshold"] = -1 }},
		{"spec.detectors[0].options.sampleInterval", func(s map[string]any) { resourceOptions(s)["sampleInterval"] = "15s" }},
		{"spec.detectors[0].options.sampleInterval", func(s map[string]any) { resourceOptions(s)["sampleInterval"] = "10m" }},
		{"spec.evaluation.rearmFor", func(s map[string]any) {
			resourceOptions(s)
			s["evaluation"].(map[string]any)["rearmFor"] = "16s"
		}},
		{"spec.evaluation.fireOnActivation", func(s map[string]any) {
			resourceOptions(s)
			s["evaluation"].(map[string]any)["fireOnActivation"] = true
		}},
	} {
		s := restartSpec()
		c.mutate(s)
		_, err := compileSpec(t, s)
		var field value.PolicyFieldError
		if !errors.As(err, &field) || field.Path != c.path {
			t.Errorf("%s: got %v", c.path, err)
		}
	}
}
