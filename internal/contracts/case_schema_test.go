package contracts

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCaseSchemaIsOnlyTheQualifiedOrdinaryPodStatusProjection(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	goodInput := []byte(`{"case_id":"00000000-0000-4000-8000-000000000002"}`)
	if wire.ValidateInput("get_case", goodInput) != nil {
		t.Fatal("valid case reference rejected")
	}
	for _, bad := range []string{`{}`, `{"case_id":"invalid"}`, `{"case_id":"00000000-0000-4000-8000-000000000002","include_raw":true}`, `{"Case_ID":"00000000-0000-4000-8000-000000000002"}`, `{"case_id":"00000000-0000-4000-8000-000000000002","case_id":"00000000-0000-4000-8000-000000000002"}`} {
		if wire.ValidateInput("get_case", []byte(bad)) == nil {
			t.Fatal("invalid input admitted", bad)
		}
	}
	sample, err := os.ReadFile("../../examples/mcp-shared-case-notice-result.json")
	if err != nil {
		t.Fatal(err)
	}
	if wire.ValidateOutput("get_case", sample) == nil {
		t.Fatal("planned shared-runtime branch silently enabled")
	}
	var result map[string]any
	if json.Unmarshal(sample, &result) != nil {
		t.Fatal("invalid example")
	}
	data := result["data"].(map[string]any)
	summary := data["case"].(map[string]any)
	summary["access"] = "ordinary"
	summary["status"] = "Ready"
	row := data["artifacts"].([]any)[0].(map[string]any)
	row["kind"] = "pod-status"
	row["data_class"] = "metadata"
	notice := row["handling_notice"].(map[string]any)
	notice["mayContain"] = []any{"personalIdentifiers", "networkAddresses", "paths"}
	good, _ := json.Marshal(result)
	if wire.ValidateOutput("get_case", good) != nil {
		t.Fatal("qualified output rejected")
	}
	for _, which := range []string{"shared", "raw", "pcap", "native checksum", "native path", "title", "timeline", "preservation", "verified classification", "deletion complete", "omitted exposure", "partial", "missing notice", "extra provenance", "pending"} {
		t.Run(which, func(t *testing.T) {
			var v map[string]any
			_ = json.Unmarshal(good, &v)
			d := v["data"].(map[string]any)
			c := d["case"].(map[string]any)
			a := d["artifacts"].([]any)[0].(map[string]any)
			n := a["handling_notice"].(map[string]any)
			switch which {
			case "shared":
				c["access"] = "shared"
			case "raw":
				a["data_class"] = "raw"
			case "pcap":
				a["kind"] = "pcapng"
			case "native checksum":
				a["sha256"] = strings.Repeat("a", 64)
			case "native path":
				a["content_path"] = "/api/v1/downloads/private/content"
			case "title":
				c["title"] = "invented title"
			case "timeline":
				d["timeline"] = []any{map[string]any{"time": "2026-10-11T12:00:00Z", "kind": "collected", "summary": "invented"}}
			case "preservation":
				n["preservationException"] = true
			case "verified classification":
				n["classification"] = "verifiedNonPersonal"
				n["mayContain"] = []any{}
			case "deletion complete":
				n["deletionState"] = "verified"
			case "omitted exposure":
				n["mayContain"] = []any{"paths"}
			case "partial":
				a["completeness"] = "partial"
			case "missing notice":
				delete(a, "handling_notice")
			case "extra provenance":
				v["provenance"] = []any{map[string]any{"private": "source"}}
			case "pending":
				v["status"] = "pending"
				v["data"] = map[string]any{"query_handle": "unknown", "retry_after_seconds": 1}
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
	if len(b) > 24<<10 || strings.Contains(string(b), `"$ref":"https:`) {
		t.Fatal("unbounded or external schema")
	}
}
