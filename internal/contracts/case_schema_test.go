package contracts

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCaseSchemaFollowsTheCanonicalContract(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, good := range []string{`{"case_id":"00000000-0000-4000-8000-000000000002"}`, `{"case_id":"00000000-0000-4000-8000-000000000002","cursor":"next","limit":50}`} {
		if wire.ValidateInput("get_case", []byte(good)) != nil {
			t.Fatal("valid case reference rejected", good)
		}
	}
	for _, bad := range []string{`{}`, `{"case_id":"invalid"}`, `{"case_id":"00000000-0000-4000-8000-000000000002","include_raw":true}`, `{"Case_ID":"00000000-0000-4000-8000-000000000002"}`, `{"case_id":"00000000-0000-4000-8000-000000000002","case_id":"00000000-0000-4000-8000-000000000002"}`, `{"case_id":"00000000-0000-4000-8000-000000000002","limit":0}`} {
		if wire.ValidateInput("get_case", []byte(bad)) == nil {
			t.Fatal("invalid input admitted", bad)
		}
	}
	sample, err := os.ReadFile("../../examples/mcp-shared-case-notice-result.json")
	if err != nil {
		t.Fatal(err)
	}
	if wire.ValidateOutput("get_case", sample) != nil {
		t.Fatal("canonical example rejected")
	}
	for _, which := range []string{"unknown access", "unknown class", "native checksum", "native path", "verified classification", "missing notice", "extra provenance"} {
		t.Run(which, func(t *testing.T) {
			var v map[string]any
			_ = json.Unmarshal(sample, &v)
			d := v["data"].(map[string]any)
			c := d["case"].(map[string]any)
			a := d["artifacts"].([]any)[0].(map[string]any)
			n := a["handling_notice"].(map[string]any)
			switch which {
			case "unknown access":
				c["access"] = "public"
			case "unknown class":
				a["data_class"] = "restricted"
			case "native checksum":
				a["sha256"] = strings.Repeat("a", 64)
			case "native path":
				a["content_path"] = "/api/v1/downloads/private/content"
			case "verified classification":
				n["classification"] = "verifiedNonPersonal"
			case "missing notice":
				delete(a, "handling_notice")
			case "extra provenance":
				v["provenance"] = []any{map[string]any{"private": "source"}}
			}
			b, _ := json.Marshal(v)
			if wire.ValidateOutput("get_case", b) == nil {
				t.Fatal("unsupported projection admitted", which)
			}
		})
	}
	tool, ok := wire.Tool("get_case")
	if !ok {
		t.Fatal("missing get_case")
	}
	b, _ := json.Marshal(tool)
	if strings.Contains(string(b), `"$ref":"https:`) {
		t.Fatal("external schema reference")
	}
}
