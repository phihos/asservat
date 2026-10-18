package contracts

import (
	"encoding/json"
	"testing"
)

func queryEnvelope() map[string]any {
	return map[string]any{"schema_version": "mcp-result/v1", "request_id": "00000000-0000-4000-8000-000000000080", "data_class": "metadata", "status": "ok", "truncated": false, "next_cursor": nil, "narrowing_hint": nil, "warnings": []string{}, "provenance": []string{}, "data": map[string]any{"logical_path": "pod-status.txt", "line_start": 1, "lines": []string{"phase: \"Running\""}, "query_observed_at": "2026-10-18T12:00:00Z", "query_expires_at": "2026-10-18T12:00:10Z"}}
}

func TestContextQueryInputAndNestedResultContracts(t *testing.T) {
	s, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]string{"get_file_excerpt": `{"case_id":"00000000-0000-4000-8000-000000000001","artifact_id":"00000000-0000-4000-8000-000000000002"}`, "get_query_result": `{"query_handle":"opaque-query"}`} {
		if err := s.ValidateInput(name, []byte(input)); err != nil {
			t.Fatalf("valid query input rejected: %s", name)
		}
		var v map[string]any
		_ = json.Unmarshal([]byte(input), &v)
		v["idempotency_key"] = "not-an-input"
		b, _ := json.Marshal(v)
		if s.ValidateInput(name, b) == nil {
			t.Fatal("caller key admitted")
		}
	}
	for _, nested := range []bool{false, true} {
		build := func() (string, map[string]any) {
			x := queryEnvelope()
			if !nested {
				return "get_file_excerpt", x
			}
			out := queryEnvelope()
			out["data"] = map[string]any{"query_handle": "opaque-query", "tool_name": "get_file_excerpt", "result": x, "query_observed_at": "2026-10-18T12:00:00Z", "query_expires_at": "2026-10-18T12:00:10Z"}
			return "get_query_result", out
		}
		name, good := build()
		b, _ := json.Marshal(good)
		if s.ValidateOutput(name, b) != nil {
			t.Fatalf("valid output rejected: %s", name)
		}
		for _, mode := range []string{"missing expiry", "invalid date", "reversed", "overlong", "wrong path", "future tool", "nested request", "nested expiry", "nested extra"} {
			if !nested && (mode == "future tool" || mode == "nested request" || mode == "nested expiry" || mode == "nested extra") {
				continue
			}
			_, v := build()
			data := v["data"].(map[string]any)
			excerpt := data
			if nested {
				excerpt = data["result"].(map[string]any)["data"].(map[string]any)
			}
			switch mode {
			case "missing expiry":
				delete(data, "query_expires_at")
			case "invalid date":
				data["query_expires_at"] = "tomorrow"
			case "reversed":
				data["query_expires_at"] = "2026-10-18T11:59:59Z"
			case "overlong":
				data["query_expires_at"] = "2026-10-18T12:01:01Z"
			case "wrong path":
				excerpt["logical_path"] = "workload-secret.txt"
			case "future tool":
				data["tool_name"] = "query_syscalls"
			case "nested request":
				data["result"].(map[string]any)["request_id"] = "00000000-0000-4000-8000-000000000081"
			case "nested expiry":
				excerpt["query_expires_at"] = "2026-10-18T12:00:11Z"
			case "nested extra":
				excerpt["native_bytes"] = "secret"
			}
			b, _ := json.Marshal(v)
			if s.ValidateOutput(name, b) == nil {
				t.Fatalf("accepted %s %s", name, mode)
			}
		}
	}
}
