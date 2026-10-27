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

// Both the harness and bootstrap consumer must agree on the owned fixture:
// one hub plus one workload cluster for this fast focus. The real service
// assertion stays strict; this test catches shape drift without starting Kind.
func TestInstalledApprovedRecordingFixtureShape(t *testing.T) {
	for _, tc := range []struct {
		focus    string
		clusters int
		fast     bool
	}{
		{"approved-recording", 2, true}, {"journey", 2, true}, {"browser", 2, true},
		{"policy", 2, true}, {"alert", 2, true}, {"logresource", 2, true},
		{"restart", 2, true}, {"upgrade", 2, true}, {"share", 2, true},
		{"chain", 2, false}, {"clusters", 3, true}, {"", 3, false}, {"unknown", 3, false},
	} {
		t.Run(tc.focus, func(t *testing.T) {
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", tc.focus)
			if got := installedClusterCount(); got != tc.clusters {
				t.Fatalf("owned fixture clusters=%d; want %d", got, tc.clusters)
			}
			if got := installedFastFixture(); got != tc.fast {
				t.Fatalf("fast feature fixture=%v; want %v", got, tc.fast)
			}
			if tc.focus == "approved-recording" && (installedRegionalInstallerChecks(1) || !installedRegionalInstallerChecks(2)) {
				t.Fatal("approved focus changed regional feature/chain coverage")
			}
		})
	}
}
