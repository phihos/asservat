package contracts

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRawPacketSummaryCanonicalCoverageField(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile("../../examples/mcp-packet-summary-result.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"raw", "raw-zero", "raw-missing", "raw-null", "raw-negative", "raw-too-large", "metadata-extra", "payload"} {
		t.Run(mode, func(t *testing.T) {
			var reply map[string]any
			if err := json.Unmarshal(base, &reply); err != nil {
				t.Fatal(err)
			}
			data := reply["data"].(map[string]any)
			data["capture_mode"], data["unclassified_packets"] = "rawPackets", 2
			data["packets"] = data["packets"].(float64) + 2
			switch mode {
			case "raw-zero":
				data["unclassified_packets"] = 0
				data["packets"] = data["packets"].(float64) - 2
			case "raw-missing":
				delete(data, "unclassified_packets")
			case "raw-null":
				data["unclassified_packets"] = nil
			case "raw-negative":
				data["unclassified_packets"] = -1
			case "raw-too-large":
				data["unclassified_packets"] = 1_000_000_000_001
			case "metadata-extra":
				data["capture_mode"] = "networkHeaders"
			case "payload":
				data["payload"] = "synthetic-raw-payload-must-not-be-an-approved-field"
			}
			valid := mode == "raw" || mode == "raw-zero"
			encoded, err := json.Marshal(reply)
			if err != nil || (wire.ValidateOutput("get_pcap_summary", encoded) == nil) != valid {
				t.Fatal("raw coverage field contract", mode, err)
			}
			outer := make(map[string]any, len(reply))
			for key, value := range reply {
				outer[key] = value
			}
			outer["provenance"] = []any{}
			outer["data"] = map[string]any{"query_handle": "original-query", "tool_name": "get_pcap_summary", "result": reply,
				"query_observed_at": data["query_observed_at"], "query_expires_at": data["query_expires_at"]}
			encoded, err = json.Marshal(outer)
			if err != nil || (wire.ValidateOutput("get_query_result", encoded) == nil) != valid {
				t.Fatal("nested raw coverage field contract", mode, err)
			}
		})
	}
}
