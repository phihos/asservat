package contracts

import (
	"encoding/json"
	"testing"
)

func TestProfileSummaryRequiresOriginalQueryTiming(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := readImplementedExample("../../examples/", "mcp-profile-result.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = wire.ValidateOutput("get_profile_summary", raw); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"missing", "reversed", "overlong", "nested expiry", "nested request"} {
		t.Run(change, func(t *testing.T) {
			var out map[string]any
			if json.Unmarshal(raw, &out) != nil {
				t.Fatal("fixture")
			}
			data := out["data"].(map[string]any)
			tool := "get_profile_summary"
			switch change {
			case "missing":
				delete(data, "query_expires_at")
			case "reversed":
				data["query_expires_at"] = data["query_observed_at"]
			case "overlong":
				data["query_expires_at"] = "2026-11-03T09:01:01Z"
			default:
				nested := out
				outer := map[string]any{}
				for key, value := range out {
					outer[key] = value
				}
				outer["data"] = map[string]any{"query_handle": "original", "tool_name": "get_profile_summary", "result": nested, "query_observed_at": data["query_observed_at"], "query_expires_at": data["query_expires_at"]}
				if change == "nested expiry" {
					data["query_expires_at"] = "2026-11-03T09:00:59Z"
				} else {
					nested["request_id"] = "00000000-0000-4000-8000-000000000099"
				}
				out, tool = outer, "get_query_result"
			}
			bad, _ := json.Marshal(out)
			if wire.ValidateOutput(tool, bad) == nil {
				t.Fatal("changed original timing admitted")
			}
		})
	}
}
