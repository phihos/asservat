package contracts

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestInvestigationArgumentEditsRetainBoundsWithSharedActionID(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	input := func(action, value string) []byte {
		return []byte(fmt.Sprintf(`{"target_ref":{"cluster":"local","namespace":"payments","kind":"Deployment","name":"api"},"profile_composition":{"components":[{"id":"calls","profileRef":{"catalog":"namespace","name":"arguments","version":"v1"},"overrides":[{"actionID":%q,"field":"syscallArguments","value":%s}]}],"maxTotalBytes":8388608,"maxDuration":"10s"}}`, action, value))
	}
	for _, action := range []string{"a", strings.Repeat("a", 63)} {
		for _, value := range []string{`{"maxBytesPerEvent":1,"captureBuffers":false}`, `{"maxBytesPerEvent":4096,"captureBuffers":true}`} {
			if err := wire.ValidateInput("preview_capture", input(action, value)); err != nil {
				t.Fatal("bounded complete argument override refused", err)
			}
		}
	}
	if wire.ValidateInput("preview_capture", input("", `{"maxBytesPerEvent":128,"captureBuffers":false}`)) == nil {
		t.Fatal("empty action ID accepted")
	}
	for _, value := range []string{
		`{"maxBytesPerEvent":0,"captureBuffers":false}`,
		`{"maxBytesPerEvent":4097,"captureBuffers":false}`,
		`{"maxBytesPerEvent":1.5,"captureBuffers":false}`,
		`{"maxBytesPerEvent":128}`,
		`{"captureBuffers":false}`,
		`{"maxBytesPerEvent":128,"captureBuffers":null}`,
		`{"maxBytesPerEvent":128,"captureBuffers":"false"}`,
		`{"maxBytesPerEvent":128,"captureBuffers":false,"extra":true}`,
	} {
		if wire.ValidateInput("preview_capture", input("calls", value)) == nil {
			t.Fatal("invalid argument override accepted", value)
		}
	}
	descriptor, _ := wire.Tool("preview_capture")
	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("preview_capture descriptor: %d bytes (unchanged 36 KiB bound)", len(raw))
}

func TestInvestigationProfileDurationUsesClosedPublicEdit(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	const raw = `{"target_ref":{"cluster":"local","namespace":"payments","kind":"Deployment","name":"api"},"profile_composition":{"components":[{"id":"cpu","profileRef":{"catalog":"builtin","name":"go-cpu","version":"v1"},"overrides":[{"actionID":"cpu","field":"profileDuration","value":"30s"}]}],"maxTotalBytes":16777216,"maxDuration":"45s"}}`
	if err := wire.ValidateInput("preview_capture", []byte(raw)); err != nil {
		t.Fatal("bounded profile edit refused", err)
	}
	for _, bad := range []string{strings.Replace(raw, "profileDuration", "profileURL", 1), strings.Replace(raw, `"30s"`, `"unbounded"`, 1)} {
		if err := wire.ValidateInput("preview_capture", []byte(bad)); err == nil {
			t.Fatal("unreviewed profile edit accepted")
		}
	}
}

func TestInvestigationCompactOverridesPreserveTypedFields(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	input := func(override string) []byte {
		return []byte(`{"target_ref":{"cluster":"local","namespace":"payments","kind":"Deployment","name":"api"},"profile_composition":{"components":[{"id":"logs","profileRef":{"catalog":"builtin","name":"logs","version":"v1"},"overrides":[` + override + `]}],"maxTotalBytes":8388608,"maxDuration":"10s"}}`)
	}
	for _, field := range []string{"packetBefore", "packetAfter", "syscallBefore", "syscallAfter", "profileDuration", "actionTimeout", "logBefore", "logAfter"} {
		for _, duration := range []string{"1s", "30s", "1h"} {
			if err := wire.ValidateInput("preview_capture", input(fmt.Sprintf(`{"actionID":"a","field":%q,"value":%q}`, field, duration))); err != nil {
				t.Fatalf("%s duration rejected: %v", field, err)
			}
		}
		for _, bad := range []string{`null`, `30`, `"forever"`, `{}`, `true`} {
			if wire.ValidateInput("preview_capture", input(fmt.Sprintf(`{"actionID":"a","field":%q,"value":%s}`, field, bad))) == nil {
				t.Fatalf("%s admitted invalid duration %s", field, bad)
			}
		}
	}
	for _, field := range []string{"profileDuration", "actionTimeout"} {
		if wire.ValidateInput("preview_capture", input(fmt.Sprintf(`{"actionID":"a","field":%q,"value":"0s"}`, field))) == nil {
			t.Fatal("positive-only duration admitted zero", field)
		}
	}
	for _, bad := range []string{
		`{"field":"logBefore","value":"1s"}`,
		`{"actionID":"a","value":"1s"}`,
		`{"actionID":"a","field":"logBefore"}`,
		`{"actionID":"a","field":"logBefore","value":"1s","extra":true}`,
		`{"actionID":"a","field":"unknown","value":"1s"}`,
		`{"actionID":"a","field":"logStream","value":"1s"}`,
		`{"actionID":"a","field":"actionMaxBytes","value":"1s"}`,
	} {
		if wire.ValidateInput("preview_capture", input(bad)) == nil {
			t.Fatal("override lost closed shape or field-specific bounds", bad)
		}
	}
}

func TestInvestigationInputsRejectUnsupportedOrAmbiguousValues(t *testing.T) {
	s, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	const target = `"target_ref":{"cluster":"local","namespace":"payments","kind":"Deployment","name":"api"}`
	const preset = `"preset_ref":{"name":"pod-status","version":"v1"}`
	for _, good := range []string{`{` + target + `,` + preset + `}`, `{` + target + `,` + preset + `,"requested_retention_seconds":60}`} {
		if err = s.ValidateInput("preview_capture", []byte(good)); err != nil {
			t.Fatalf("valid input: %v", err)
		}
	}
	for name, bad := range map[string]string{
		"null lifetime":   `{` + target + `,` + preset + `,"requested_retention_seconds":null}`,
		"explicit zero":   `{` + target + `,` + preset + `,"requested_retention_seconds":0}`,
		"fraction":        `{` + target + `,` + preset + `,"requested_retention_seconds":0.5}`,
		"duplicate":       `{` + target + `,` + preset + `,` + preset + `}`,
		"case alias":      `{` + target + `,` + strings.ReplaceAll(preset, "preset_ref", "Preset_Ref") + `}`,
		"trailing object": `{` + target + `,` + preset + `} {}`,
		"deep":            strings.Repeat("[", 34) + strings.Repeat("]", 34),
		"oversize":        strings.Repeat(" ", InvestigationInputLimit+1),
	} {
		t.Run(name, func(t *testing.T) {
			if s.ValidateInput("preview_capture", []byte(bad)) == nil {
				t.Fatal("invalid input admitted")
			}
		})
	}
	for _, name := range []string{"list_diagnostics", "preview_capture", "request_capture", "get_capture"} {
		d, ok := s.Tool(name)
		if !ok {
			t.Fatal(name)
		}
		if strings.Contains(string(d.InputSchema), `"$ref":"https:`) || strings.Contains(string(d.OutputSchema), `"$ref": "https:`) {
			t.Fatal("runtime network schema reference")
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

// readImplementedExample reads the example this runtime implements:
// examples/implemented/ (pre-ADR-330 contracts) when present, otherwise the
// canonical example.
func readImplementedExample(dir, name string) ([]byte, error) {
	if b, err := os.ReadFile(dir + "implemented/" + name); err == nil {
		return b, nil
	}
	return os.ReadFile(dir + name)
}
