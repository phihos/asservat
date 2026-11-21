package contracts

import (
	"encoding/json"
	"testing"
)

func TestRawLogCaptureTypedWindowAndCombinedStreamInput(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"target_ref":{"cluster":"local","namespace":"payments","kind":"Deployment","name":"api"},"profile_composition":{"components":[{"id":"saved","profileRef":{"catalog":"builtin","name":"finite-logs","version":"v1"},"overrides":[{"actionID":"logs","field":"logBefore","value":"1h"},{"actionID":"logs","field":"logAfter","value":"30s"},{"actionID":"logs","field":"logStream","value":"both"}]}],"maxTotalBytes":1048576,"maxDuration":"40s"}}`)
	if wire.ValidateInput("preview_capture", input) != nil {
		t.Fatal("declared log edits refused")
	}
	for _, invalid := range []string{`0`, `null`, `"stdout"`, `"stderr"`} {
		var v map[string]any
		_ = json.Unmarshal(input, &v)
		edits := v["profile_composition"].(map[string]any)["components"].([]any)[0].(map[string]any)["overrides"].([]any)
		var value any
		_ = json.Unmarshal([]byte(invalid), &value)
		edits[2].(map[string]any)["value"] = value
		b, _ := json.Marshal(v)
		if wire.ValidateInput("preview_capture", b) == nil {
			t.Fatal("unqualified split stream or untyped edit advertised", invalid)
		}
	}
}
