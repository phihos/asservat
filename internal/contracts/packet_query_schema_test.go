package contracts

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPacketQuerySchemasAndNestedPage(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"metadata", "raw"} {
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile("../../examples/mcp-packet-query-" + name + "-input.json")
			if err != nil || wire.ValidateInput("pcap_query", input) != nil {
				t.Fatal("packet query input", err)
			}
			body, err := os.ReadFile("../../examples/mcp-packet-query-" + name + "-result.json")
			if err != nil || wire.ValidateOutput("pcap_query", body) != nil {
				t.Fatal("packet query page", err)
			}
			var page map[string]any
			if err = json.Unmarshal(body, &page); err != nil {
				t.Fatal(err)
			}
			data := page["data"].(map[string]any)
			outer := make(map[string]any, len(page))
			for key, value := range page {
				outer[key] = value
			}
			outer["provenance"] = []any{}
			outer["data"] = map[string]any{"query_handle": "00000000-0000-4000-8000-000000000091", "tool_name": "pcap_query", "result": page,
				"query_observed_at": data["query_observed_at"], "query_expires_at": data["query_expires_at"]}
			encoded, _ := json.Marshal(outer)
			if wire.ValidateOutput("get_query_result", encoded) != nil {
				t.Fatal("nested packet query refused")
			}
			if name == "raw" {
				outer["data_class"] = "extract"
				encoded, _ = json.Marshal(outer)
				if wire.ValidateOutput("get_query_result", encoded) == nil {
					t.Fatal("raw nested page was relabeled as an extract")
				}
			}
			data["query_expires_at"] = "2026-11-05T09:02:00Z"
			encoded, _ = json.Marshal(page)
			if wire.ValidateOutput("pcap_query", encoded) == nil {
				t.Fatal("packet query view exceeded its original maximum lifetime")
			}
		})
	}
}

func TestPacketQueryCombinedReviewChoicesAndCurrentClientDefault(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"preview_id":"00000000-0000-4000-8000-000000000173","idempotency_key":"review","result_access":{"actionIds":["packets"],"operations":["download_artifact","pcap_query"],"maxArtifacts":1,"maxBytes":9000000,"maxOperations":10,"notAfter":"2026-11-05T10:00:00Z"}}`)
	if err := wire.ValidateInput("request_capture", input); err != nil {
		t.Fatal("current-client request", err)
	}
	body, err := readImplementedExample("../../examples/", "mcp-composition-preview-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]any
	if err := json.Unmarshal(body, &output); err != nil {
		t.Fatal(err)
	}
	data := output["data"].(map[string]any)
	podBody, err := readImplementedExample("../../examples/", "mcp-pod-status-preview-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var pod map[string]any
	if err := json.Unmarshal(podBody, &pod); err != nil {
		t.Fatal(err)
	}
	podData := pod["data"].(map[string]any)
	data["target_ref"], data["selected_pods"] = podData["target_ref"], podData["selected_pods"]
	data["capture_enabled"] = false
	data["blockers"] = []any{map[string]any{"code": "ApprovalRequired", "message": "Independent review required.", "responsible_role": "approver", "retryable": false}}
	data["result_access_actions"] = []any{map[string]any{"action_id": "packets", "operations": []string{"download_artifact", "pcap_query"}}}
	encoded, _ := json.Marshal(output)
	if err := wire.ValidateOutput("preview_capture", encoded); err != nil {
		t.Fatal("compiled plan choices", err)
	}
	data["result_access_actions"] = []any{map[string]any{"action_id": "packets", "operations": []string{"read_memory"}}}
	encoded, _ = json.Marshal(output)
	if wire.ValidateOutput("preview_capture", encoded) == nil {
		t.Fatal("unimplemented query operation advertised")
	}
}

func TestLimitedPacketQueryRequiresCanonicalNarrowingHint(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("../../examples/mcp-packet-query-raw-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var page map[string]any
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	page["truncated"], page["narrowing_hint"] = true, "Narrow the packet filter or time interval."
	data := page["data"].(map[string]any)
	data["row_limit_reached"] = true
	encoded, _ := json.Marshal(page)
	if err := wire.ValidateOutput("pcap_query", encoded); err != nil {
		t.Fatal("canonical limited page rejected", err)
	}
	outer := make(map[string]any, len(page))
	for k, v := range page {
		outer[k] = v
	}
	outer["truncated"], outer["narrowing_hint"], outer["provenance"] = false, nil, []any{}
	outer["data"] = map[string]any{"query_handle": "00000000-0000-4000-8000-000000000091", "tool_name": "pcap_query", "result": page, "query_observed_at": data["query_observed_at"], "query_expires_at": data["query_expires_at"]}
	encoded, _ = json.Marshal(outer)
	if err := wire.ValidateOutput("get_query_result", encoded); err != nil {
		t.Fatal("nested canonical limited page rejected", err)
	}
	page["narrowing_hint"] = nil
	for _, tool := range []string{"pcap_query", "get_query_result"} {
		v := page
		if tool == "get_query_result" {
			v = outer
		}
		encoded, _ = json.Marshal(v)
		if wire.ValidateOutput(tool, encoded) == nil {
			t.Fatal("limited page without narrowing hint admitted", tool)
		}
	}
}
