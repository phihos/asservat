package contracts

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// ADR-282 slice 4: the runtime get_http_headers subset accepts the canonical
// example and rejects bodies, credential headers, pending replies, oversized
// pages and cursors that are not the bounded record index.
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
		"pending": mutate(func(v map[string]any) {
			v["status"], v["data"] = "pending", map[string]any{"query_handle": "q", "retry_after_seconds": 1}
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
}
