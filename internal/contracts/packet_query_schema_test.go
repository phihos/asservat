package contracts

import (
	"encoding/json"
	"testing"
)

func TestPacketQueryCombinedReviewChoicesAndCurrentClientDefault(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"preview":{"target_ref":{"cluster_id":"00000000-0000-4000-8000-000000000001","namespace":"payments","kind":"Deployment","name":"api"},"preset_ref":{"name":"pod-status","version":"v1"}},"expected_plan_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","idempotency_key":"review","result_access":{"actionIds":["packets"],"operations":["download_artifact","pcap_query"],"maxArtifacts":1,"maxBytes":9000000,"maxOperations":10,"notAfter":"2026-11-05T10:00:00Z"}}`)
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
