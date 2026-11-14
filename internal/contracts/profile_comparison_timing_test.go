package contracts

import (
	"encoding/json"
	"testing"
)

func TestProfileComparisonRequiresOriginalPairTiming(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := readImplementedExample("../../examples/", "mcp-profile-comparison-result.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = wire.ValidateOutput("compare_profiles", raw); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"missing baseline", "missing version", "reversed", "overlong", "nested expiry", "nested request"} {
		t.Run(change, func(t *testing.T) {
			var out map[string]any
			if json.Unmarshal(raw, &out) != nil {
				t.Fatal("fixture")
			}
			data := out["data"].(map[string]any)
			tool := "compare_profiles"
			switch change {
			case "missing baseline":
				delete(data, "baseline_case_id")
			case "missing version":
				delete(data, "baseline_source_version")
			case "reversed":
				data["query_expires_at"] = data["query_observed_at"]
			case "overlong":
				data["query_expires_at"] = "2026-11-03T09:02:00Z"
			default:
				outer := map[string]any{}
				for k, v := range out {
					outer[k] = v
				}
				outer["provenance"] = []any{}
				outer["data"] = map[string]any{"query_handle": "original", "tool_name": "compare_profiles", "result": out, "query_observed_at": data["query_observed_at"], "query_expires_at": data["query_expires_at"]}
				if change == "nested expiry" {
					data["query_expires_at"] = "2026-11-03T09:00:59Z"
				} else {
					out["request_id"] = "00000000-0000-4000-8000-000000000099"
				}
				out, tool = outer, "get_query_result"
			}
			bad, _ := json.Marshal(out)
			if wire.ValidateOutput(tool, bad) == nil {
				t.Fatal("altered pair envelope admitted")
			}
		})
	}
}
