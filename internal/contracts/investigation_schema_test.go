package contracts

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestInvestigationInputsRejectUnsupportedOrAmbiguousValues(t *testing.T) {
	s, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	const target = `"target_ref":{"cluster_id":"00000000-0000-4000-8000-000000000001","namespace":"payments","kind":"Deployment","name":"api"}`
	const preset = `"preset_ref":{"name":"pod-status","version":"v1"}`
	for _, good := range []string{`{` + target + `,` + preset + `}`, `{` + target + `,` + preset + `,"requested_retention_seconds":60}`} {
		if err = s.ValidateInput("preview_capture", []byte(good)); err != nil {
			t.Fatalf("valid input: %v", err)
		}
	}
	for name, bad := range map[string]string{
		"null lifetime":         `{` + target + `,` + preset + `,"requested_retention_seconds":null}`,
		"explicit zero":         `{` + target + `,` + preset + `,"requested_retention_seconds":0}`,
		"fraction":              `{` + target + `,` + preset + `,"requested_retention_seconds":0.5}`,
		"duplicate":             `{` + target + `,` + preset + `,` + preset + `}`,
		"case alias":            `{` + target + `,` + strings.ReplaceAll(preset, "preset_ref", "Preset_Ref") + `}`,
		"broad preset":          `{` + target + `,` + strings.ReplaceAll(preset, "pod-status", "incident-context") + `}`,
		"reason not discarded":  `{` + target + `,` + preset + `,"reason":"user data"}`,
		"sharing not discarded": `{` + target + `,` + preset + `,"sharing":{}}`,
		"trailing object":       `{` + target + `,` + preset + `} {}`,
		"deep":                  strings.Repeat("[", 34) + strings.Repeat("]", 34),
		"oversize":              strings.Repeat(" ", InvestigationInputLimit+1),
	} {
		t.Run(name, func(t *testing.T) {
			if s.ValidateInput("preview_capture", []byte(bad)) == nil {
				t.Fatal("invalid input admitted")
			}
		})
	}
	for _, name := range []string{"list_diagnostics", "preview_capture", "request_capture", "resolve_capture_request", "get_capture"} {
		d, ok := s.Tool(name)
		if !ok {
			t.Fatal(name)
		}
		if strings.Contains(string(d.InputSchema), `"$ref":"https:`) || strings.Contains(string(d.OutputSchema), `"$ref": "https:`) {
			t.Fatal("runtime network schema reference")
		}
		b, _ := json.Marshal(d)
		if len(b) > 24<<10 {
			t.Fatal("tool description exceeds bounded discovery budget")
		}
		d.InputSchema[0] = 'x'
		again, _ := s.Tool(name)
		if again.InputSchema[0] == 'x' {
			t.Fatal("caller mutated shared schema")
		}
	}
}

func TestPodStatusOutputRequiresSubmissionRetentionAnchor(t *testing.T) {
	s, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../examples/mcp-pod-status-preview-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err = json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	data := result["data"].(map[string]any)
	actions := data["capture_assessment"].(map[string]any)["actions"].([]any)
	r := actions[0].(map[string]any)["retention"].(map[string]any)
	for _, anchor := range []string{"submissionPreparation", "firstAcquisitionOrEarlierSource", "uploadCompletion"} {
		r["anchorRule"] = anchor
		b, err = json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if valid := s.ValidateOutput("preview_capture", b) == nil; valid != (anchor == "submissionPreparation") {
			t.Fatalf("pod-status anchor %q validity %v", anchor, valid)
		}
	}
}

func TestCaptureRequestResolutionHasStrictAcknowledgedDisposition(t *testing.T) {
	s, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	const pair = `{"preview_id":"00000000-0000-4000-8000-000000000173","idempotency_key":"original-key"}`
	if err = s.ValidateInput("resolve_capture_request", []byte(pair)); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`,"target_ref":{}`, `,"force":true`, `,"capture_id":"00000000-0000-4000-8000-000000000008"`, `,"preview_id":"00000000-0000-4000-8000-000000000999"`} {
		if s.ValidateInput("resolve_capture_request", []byte(strings.TrimSuffix(pair, "}")+extra+"}")) == nil {
			t.Fatal("accepted altered resolution input", extra)
		}
	}
	for _, example := range []string{"mcp-resolve-capture-accepted.json", "mcp-resolve-capture-closed.json"} {
		b, err := os.ReadFile("../../examples/" + example)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.ValidateOutput("resolve_capture_request", b); err != nil {
			t.Fatal(example, err)
		}
		var result map[string]any
		if err = json.Unmarshal(b, &result); err != nil {
			t.Fatal(err)
		}
		for _, data := range []map[string]any{
			{"state": "pending"}, {"state": "accepted"},
			{"state": "closed", "capture_id": "00000000-0000-4000-8000-000000000008"},
			{"state": "closed", "target_ref": map[string]any{"name": "private"}},
			{"state": "closed", "phase": "Accepted"}, {"state": "closed", "operation": "collect"},
		} {
			result["data"] = data
			invalid, _ := json.Marshal(result)
			if s.ValidateOutput("resolve_capture_request", invalid) == nil {
				t.Fatal("accepted unknown, incomplete or mixed disposition", data)
			}
		}
		result["data"] = map[string]any{"state": "closed"}
		result["warnings"] = []string{"private target"}
		invalidEnvelope, _ := json.Marshal(result)
		if s.ValidateOutput("resolve_capture_request", invalidEnvelope) == nil {
			t.Fatal("closure conveyed warning metadata")
		}
		result["warnings"] = []string{}
		result["status"] = "pending"
		result["data"] = map[string]any{"state": "closed"}
		invalid, _ := json.Marshal(result)
		if s.ValidateOutput("resolve_capture_request", invalid) == nil {
			t.Fatal("pending envelope conveyed closure")
		}
	}
}

func TestCaptureContinuationStrictInputAndPassiveAlternatives(t *testing.T) {
	s, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	const pair = `{"preview_id":"00000000-0000-4000-8000-000000000173","idempotency_key":"original-key"`
	if err = s.ValidateInput("request_capture", []byte(pair+`,"continue_acquisition":true}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{pair + `,"continue_acquisition":false}`, pair + `,"continue_acquisition":"true"}`, `{"idempotency_key":"original-key","continue_acquisition":true}`, pair + `,"continue_acquisition":true,"capture_id":"00000000-0000-4000-8000-000000000008"}`} {
		if s.ValidateInput("request_capture", []byte(bad)) == nil {
			t.Fatal("accepted implicit/mixed continuation", bad)
		}
	}
	if s.ValidateInput("resolve_capture_request", []byte(pair+`,"continue_acquisition":true}`)) == nil || s.ValidateInput("get_capture", []byte(`{"capture_id":"00000000-0000-4000-8000-000000000008","continue_acquisition":true}`)) == nil {
		t.Fatal("passive operation accepted acquisition switch")
	}
}
