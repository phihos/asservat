package integration

import (
	"os"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"sigs.k8s.io/yaml"
)

// helmContextTrialSettings are the canonical context-trial profile's capacity
// and federation bounds (top-level chart values with the former installer
// field names). It supplies no endpoint, credential or generated ID.
type helmContextTrialSettings struct {
	Public *contracts.InstallerPublicSettings
}

func helmContextTrialProfile(t *testing.T) helmContextTrialSettings {
	t.Helper()
	raw, err := os.ReadFile("../../examples/helm/context-trial-profile.yaml")
	if err != nil {
		t.Fatal("canonical context trial profile", err)
	}
	var document struct {
		Capacity   *contracts.CapacityValues              `json:"capacity"`
		Federation *contracts.InstallerFederationSettings `json:"federation"`
		Retention  *contracts.InstallerRetentionBaseline  `json:"retention"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal("decode canonical context trial profile", err)
	}
	if document.Capacity == nil || document.Capacity.EvidenceStorage == "" || document.Federation == nil || document.Retention == nil {
		t.Fatal("canonical context trial lacks its complete declared profile")
	}
	return helmContextTrialSettings{Public: &contracts.InstallerPublicSettings{Federation: document.Federation, RetentionBaseline: document.Retention}}
}
