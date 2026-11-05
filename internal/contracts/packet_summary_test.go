package contracts

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPacketSummaryCanonicalRepliesAndOriginalFiniteView(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mcp-packet-summary-result.json", "mcp-packet-summary-unreported-result.json"} {
		raw, err := os.ReadFile("../../examples/" + name)
		if err != nil || wire.ValidateOutput("get_pcap_summary", raw) != nil {
			t.Fatal("canonical packet summary refused", name, err)
		}
		for _, mode := range []string{"reversed", "too-long", "missing-time", "payload", "unknown-counter", "text-counter"} {
			t.Run(name+mode, func(t *testing.T) {
				var reply map[string]any
				if err := json.Unmarshal(raw, &reply); err != nil {
					t.Fatal(err)
				}
				data := reply["data"].(map[string]any)
				switch mode {
				case "reversed":
					data["query_expires_at"] = "2026-11-05T08:59:59Z"
				case "too-long":
					data["query_expires_at"] = "2026-11-05T09:01:01Z"
				case "missing-time":
					delete(data, "query_observed_at")
				case "payload":
					data["payload"] = "forbidden"
				case "unknown-counter":
					data["drop_reporting"] = "measuredNetworkLoss"
				case "text-counter":
					data["drops"] = "zero"
				}
				changed, _ := json.Marshal(reply)
				if wire.ValidateOutput("get_pcap_summary", changed) == nil {
					t.Fatal("malformed/extended packet reply accepted", mode)
				}
			})
		}
	}
}
