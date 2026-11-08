package integration

import (
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestInstalledLiveObservationUsesFastOriginalTopology(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "live-observation")
	if !installedFastFixture() {
		t.Fatal("live feature would repeat unrelated installation qualification instead of the original fast real installer")
	}
}

func TestInstalledLivePolicyGrantInputsMatchObservationWindows(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, projection := range []string{"packetMetadata", "syscallMetadata", "httpHeaders"} {
		in := installedLivePolicyGrantInput("live", "10000000-0000-4000-8000-000000000001", projection)
		raw, _ := json.Marshal(in)
		if err := wire.ValidateInput("request_policy_grant", raw); err != nil {
			t.Fatal(projection, err)
		}
		_, window := in["observation_limits"]
		observed := in["limits"].(map[string]any)["max_observed_bytes"]
		if window != (projection == "httpHeaders") || (observed == 0) == window {
			t.Fatal(projection, "observed bytes without an observation window", observed)
		}
	}
}
