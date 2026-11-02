package contracts

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// ADR-282: the runtime get_http_headers contract accepts the canonical
// example and the canonical pending handle, and rejects bodies, credential
// headers, oversized pages and cursors that are not the bounded record index.
func TestHTTPHeadersContract(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	if tool, ok := wire.Tool("get_http_headers"); !ok || !tool.MCP() {
		t.Fatal("get_http_headers is not a shared browser/MCP contract")
	}
	sample, err := os.ReadFile("../../examples/mcp-http-headers-result.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateOutput("get_http_headers", sample); err != nil {
		t.Fatal("example", err)
	}
	for _, in := range []string{
		`{"case_id":"00000000-0000-4000-8000-000000000001","artifact_id":"00000000-0000-4000-8000-000000000002"}`,
		`{"case_id":"00000000-0000-4000-8000-000000000001","artifact_id":"00000000-0000-4000-8000-000000000002","cursor":"100:` + strings.Repeat("a", 32) + `","limit":100}`,
	} {
		if err := wire.ValidateInput("get_http_headers", []byte(in)); err != nil {
			t.Fatal(in, err)
		}
	}
	for _, in := range []string{
		`{"case_id":"00000000-0000-4000-8000-000000000001","artifact_id":"00000000-0000-4000-8000-000000000002","limit":101}`,
		`{"case_id":"00000000-0000-4000-8000-000000000001","artifact_id":"00000000-0000-4000-8000-000000000002","include_body":true}`,
		`{"case_id":"00000000-0000-4000-8000-000000000001","artifact_id":"00000000-0000-4000-8000-000000000002","headers":["cookie"]}`,
		`{"case_id":"00000000-0000-4000-8000-000000000001"}`,
	} {
		if wire.ValidateInput("get_http_headers", []byte(in)) == nil {
			t.Fatal("accepted", in)
		}
	}
	mutate := func(edit func(map[string]any)) []byte {
		var v map[string]any
		if err := json.Unmarshal(sample, &v); err != nil {
			t.Fatal(err)
		}
		edit(v)
		b, _ := json.Marshal(v)
		return b
	}
	record := func(v map[string]any) map[string]any {
		return v["data"].(map[string]any)["records"].([]any)[0].(map[string]any)
	}
	for name, b := range map[string][]byte{
		"credential header": mutate(func(v map[string]any) {
			record(v)["headers"] = []any{map[string]any{"name": "set-cookie", "value": "s=1"}}
		}),
		"body": mutate(func(v map[string]any) { record(v)["body"] = "x" }),
		"pending with times": mutate(func(v map[string]any) {
			v["status"], v["data"] = "pending", map[string]any{"query_handle": "q", "retry_after_seconds": 1, "query_observed_at": "2026-11-02T10:00:00Z"}
		}),
		"free cursor": mutate(func(v map[string]any) { v["next_cursor"] = "page-2" }),
		"two provenances": mutate(func(v map[string]any) {
			v["provenance"] = append(v["provenance"].([]any), map[string]any{"artifactID": "00000000-0000-4000-8000-000000000052", "digest": strings.Repeat("9", 64)})
		}),
		"truncated":   mutate(func(v map[string]any) { v["truncated"], v["narrowing_hint"] = true, "narrow" }),
		"metadata ok": mutate(func(v map[string]any) { v["data_class"] = "metadata" }),
	} {
		if wire.ValidateOutput("get_http_headers", b) == nil {
			t.Fatal("accepted", name)
		}
	}
	if err := wire.ValidateOutput("get_http_headers", mutate(func(v map[string]any) { v["next_cursor"] = "100:" + strings.Repeat("0", 32) })); err != nil {
		t.Fatal("bounded cursor", err)
	}
	// ADR-282 slice 5: each page is an approved query; Begin answers with
	// the canonical pending handle.
	pending := mutate(func(v map[string]any) {
		v["status"], v["data_class"], v["warnings"], v["provenance"], v["next_cursor"] = "pending", "metadata", []any{}, []any{}, nil
		v["data"] = map[string]any{"query_handle": "00000000-0000-4000-8000-000000000053", "retry_after_seconds": 1}
	})
	if err := wire.ValidateOutput("get_http_headers", pending); err != nil {
		t.Fatal("pending", err)
	}
}

// get_query_result serves a get_http_headers page as its nested result: the
// page of the same request, as an extract; other nested tools stay closed.
func TestQueryResultServesHTTPHeaderPage(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	sample, err := os.ReadFile("../../examples/mcp-http-headers-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var page map[string]any
	if json.Unmarshal(sample, &page) != nil {
		t.Fatal("sample")
	}
	poll := func(tool string, edit func(map[string]any)) []byte {
		inner := map[string]any{}
		for k, v := range page {
			inner[k] = v
		}
		edit(inner)
		b, _ := json.Marshal(map[string]any{"schema_version": page["schema_version"], "request_id": page["request_id"], "status": "ok", "data_class": "extract",
			"warnings": []any{}, "provenance": []any{}, "truncated": false, "next_cursor": nil, "narrowing_hint": nil,
			"data": map[string]any{"query_handle": "00000000-0000-4000-8000-000000000054", "tool_name": tool, "result": inner,
				"query_observed_at": "2026-11-02T10:00:00Z", "query_expires_at": "2026-11-02T10:00:10Z"}})
		return b
	}
	if err := wire.ValidateOutput("get_query_result", poll("get_http_headers", func(map[string]any) {})); err != nil {
		t.Fatal("nested page", err)
	}
	for name, b := range map[string][]byte{
		"other request": poll("get_http_headers", func(v map[string]any) { v["request_id"] = "00000000-0000-4000-8000-000000000055" }),
		"not a page": poll("get_http_headers", func(v map[string]any) {
			v["status"], v["data"] = "error", map[string]any{"code": "X", "message": "m", "retryable": false}
		}),
		"invalid page": poll("get_http_headers", func(v map[string]any) { v["data_class"] = "metadata" }),
		"other tool":   poll("get_case", func(map[string]any) {}),
	} {
		if wire.ValidateOutput("get_query_result", b) == nil {
			t.Fatal("accepted", name)
		}
	}
}
