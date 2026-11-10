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

func TestInstalledLiveSettingsKeepNestedCeilingsValid(t *testing.T) {
	paths := []contracts.DownloadEnvironmentPath{{ID: "path", TargetClusterID: "cluster"}}
	clients := []contracts.DownloadEnvironmentClient{{Issuer: "issuer", ID: "console", Kind: "human", PathIDs: []string{"path"}}, {Issuer: "issuer", ID: "mcp", Kind: "human", PathIDs: []string{"path"}}}
	settings, err := installedLiveSettings(contracts.DownloadEnvironmentSettings{Format: contracts.DownloadEnvironmentFormat, RootID: "root", Revision: 1, Paths: paths, Clients: clients}, "root", "cluster", "issuer")
	if err != nil {
		t.Fatal(err)
	}
	root := settings.LiveRead.Root
	if root.Watches != 3 || root.PrincipalWatches != 2 || root.WorkloadWatches != 3 || root.PrincipalWatches > root.Watches || root.WorkloadWatches > root.Watches {
		t.Fatal("invalid nested installed live ceilings", root)
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
