package capture

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	value "asservat.local/asservat/internal/domain/capture"
)

// alertOptions replaces the spec's detector with a valid alert detector
// (ADR-231; the spec keeps rearmFor 10s) and returns the options for a test
// to change.
func alertOptions(s map[string]any) map[string]any {
	options := map[string]any{"receiverRef": "alertmanager", "status": "firing", "matchLabels": map[string]any{"alertname": "HighErrorRate", "severity": "critical"}}
	s["detectors"] = []any{map[string]any{"id": "crash", "kind": "alert", "options": options}}
	return options
}

func TestAlertPolicyCompiles(t *testing.T) {
	s := restartSpec()
	alertOptions(s)
	p, err := compileSpec(t, s)
	if err != nil || !p.Valid() || p.Kind() != value.DetectorAlert || p.AlertLabels["alertname"] != "HighErrorRate" || p.AlertLabels["severity"] != "critical" || p.Reasons != nil || p.ProbeType != "" {
		t.Fatalf("compiled %+v %v", p, err)
	}
	if r := p.Request(); !r.Alert || len(r.AlertLabels) != 2 || r.Probe != "" || !r.Valid() {
		t.Fatal("request", r)
	}
	// Without matchLabels every active alert naming a Pod of the workload counts.
	delete(alertOptions(s), "matchLabels")
	if p, err = compileSpec(t, s); err != nil || !p.Valid() || p.AlertLabels != nil {
		t.Fatal("no labels", p, err)
	}
	spec, _ := json.Marshal(s)
	if d, ok := DescribePolicyDetector(spec); !ok || d.Kind != "alert" {
		t.Fatal("alert description", d, ok)
	}
	// An exit policy's compiled JSON (its scope digest input) is unchanged.
	exit, _ := compileSpec(t, restartSpec())
	if b, _ := json.Marshal(exit); strings.Contains(string(b), "Alert") {
		t.Fatal("exit policy JSON changed", string(b))
	}
}

func TestAlertPolicyRejectsWithPath(t *testing.T) {
	for _, c := range []struct {
		path   string
		mutate func(map[string]any)
	}{
		{"spec.detectors[0].options.receiverRef", func(s map[string]any) { alertOptions(s)["receiverRef"] = "team-webhook" }},
		{"spec.detectors[0].options.status", func(s map[string]any) { alertOptions(s)["status"] = "resolved" }},
		{"spec.detectors[0].options.matchLabels.pod", func(s map[string]any) { alertOptions(s)["matchLabels"] = map[string]any{"pod": "api-0"} }},
		{"spec.detectors[0].options.matchLabels.namespace", func(s map[string]any) { alertOptions(s)["matchLabels"] = map[string]any{"namespace": "other"} }},
		{"spec.detectors[0].options.matchLabels", func(s map[string]any) { alertOptions(s)["matchLabels"] = map[string]any{"bad-name": "x"} }},
		{"spec.detectors[0].eventWindow", func(s map[string]any) {
			alertOptions(s)
			s["detectors"].([]any)[0].(map[string]any)["eventWindow"] = "30s"
		}},
		{"spec.evaluation.rearmFor", func(s map[string]any) {
			alertOptions(s)
			s["evaluation"].(map[string]any)["rearmFor"] = "16s"
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
