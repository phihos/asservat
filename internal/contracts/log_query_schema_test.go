package contracts

import (
	"encoding/json"
	"testing"
)

func TestRawLogQueryStableInvocationAndPrimitiveOutput(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	input, err := readImplementedExample("../../examples/", "mcp-logs-input.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = wire.ValidateInput("get_logs", input); err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	_ = json.Unmarshal(input, &request)
	delete(request, "grant_id")
	b, _ := json.Marshal(request)
	if wire.ValidateInput("get_logs", b) != nil {
		t.Fatal("missing grant must reach review remedy")
	}
	delete(request, "idempotency_key")
	b, _ = json.Marshal(request)
	if wire.ValidateInput("get_logs", b) == nil {
		t.Fatal("missing stable key accepted")
	}
	body, err := readImplementedExample("../../examples/", "mcp-logs-result.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = wire.ValidateOutput("get_logs", body); err != nil {
		t.Fatal("canonical empty-line/unknown-time example", err)
	}
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["data_class"] = "extract" },
		func(v map[string]any) { v["data"].(map[string]any)["query_expires_at"] = "2026-11-05T12:01:59Z" },
		func(v map[string]any) { v["data"].(map[string]any)["query_expires_at"] = "2026-11-05T12:03:01Z" },
		func(v map[string]any) {
			v["data"].(map[string]any)["entries"].([]any)[0].(map[string]any)["bytes_base64"] = "Cg=="
		},
		func(v map[string]any) {
			v["data"].(map[string]any)["entries"].([]any)[0].(map[string]any)["source_time"] = 0
		},
		func(v map[string]any) {
			v["data"].(map[string]any)["entries"].([]any)[0].(map[string]any)["origin"].(map[string]any)["record"] = "origin"
		},
	} {
		var v map[string]any
		_ = json.Unmarshal(body, &v)
		mutate(v)
		b, _ := json.Marshal(v)
		if wire.ValidateOutput("get_logs", b) == nil {
			t.Fatal("invalid raw log output accepted", string(b))
		}
	}
	var v map[string]any
	_ = json.Unmarshal(body, &v)
	row := v["data"].(map[string]any)["entries"].([]any)[0].(map[string]any)
	row["text"] = nil
	row["bytes_base64"] = "/wo="
	b, _ = json.Marshal(v)
	if wire.ValidateOutput("get_logs", b) != nil {
		t.Fatal("original invalid UTF8 bytes must remain representable")
	}
}

func TestRawLogCaptureTypedWindowAndCombinedStreamInput(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"target_ref":{"cluster_id":"00000000-0000-4000-8000-000000000001","namespace":"payments","kind":"Deployment","name":"api"},"profile_composition":{"components":[{"id":"saved","profileRef":{"catalog":"builtin","name":"finite-logs","version":"v1"},"overrides":[{"actionID":"logs","field":"logBefore","value":"1h"},{"actionID":"logs","field":"logAfter","value":"30s"},{"actionID":"logs","field":"logStream","value":"both"}]}],"maxTotalBytes":1048576,"maxDuration":"40s"}}`)
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
