package integration

import (
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

// This is a separate reviewed public capture request, before independent
// approval. It does not lengthen the accepted PR-100 recording or its deadlines.
func nativePacingArguments(cluster, namespace, workload string) map[string]any {
	input := approvedRecordingArguments(cluster, namespace, workload)
	composition := input["profile_composition"].(map[string]any)
	component := composition["components"].([]any)[0].(map[string]any)
	component["overrides"] = []any{
		map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
		map[string]any{"actionID": "sample", "field": "packetAfter", "value": "10s"},
		map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "20s"},
		map[string]any{"actionID": "sample", "field": "actionMaxBytes", "value": artifact.RecordingNativeLimit},
	}
	composition["maxDuration"] = "20s"
	return input
}

func TestNativePacingReviewedCaptureInput(t *testing.T) {
	const cluster = "00000000-0000-4000-8000-000000000001"
	ordinary, err := json.Marshal(approvedRecordingArguments(cluster, "payments", "api"))
	if err != nil {
		t.Fatal(err)
	}
	input := nativePacingArguments(cluster, "payments", "api")
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateInput("preview_capture", raw); err != nil {
		t.Fatal("reviewed finite pacing request is not a public capture input", err)
	}
	composition := input["profile_composition"].(map[string]any)
	if composition["maxTotalBytes"] != 16<<20 || composition["maxDuration"] != "20s" {
		t.Fatal("qualification changed aggregate byte ceiling or lost finite duration")
	}
	after, _ := json.Marshal(approvedRecordingArguments(cluster, "payments", "api"))
	if string(after) != string(ordinary) {
		t.Fatal("pacing request changed the original approved-recording fixture")
	}
}
