package integration

import (
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// Invalid request wiring should fail before spending an installed collector run.
// Contract validation grants no capture authority and runs no collector.
func TestInstalledApprovedRecordingPublicInput(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	input := approvedRecordingArguments("00000000-0000-4000-8000-000000000001", "payments", "api")
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateInput("preview_capture", raw); err != nil {
		t.Fatal("actual approved recording preview input", err)
	}
}
