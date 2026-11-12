package bootstrap

import (
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

func TestInitialSeaweedWriterUsesOnlyOriginalStoredMaterialAndBounds(t *testing.T) {
	original, err := providerconfig.GenerateSeaweedStorageCredential()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	state := contracts.InitialBootstrapState{InstallationID: "10000000-0000-4000-8000-000000000001", RequestID: "10000000-0000-4000-8000-000000000002", Material: &contracts.InitialBootstrapMaterial{Storage: original, StorageUseUntil: now.Add(time.Minute)}}
	c, err := initialSeaweedCredential(state, now)
	if err != nil || c.Principal.ScopeID != state.InstallationID || c.Principal.Purpose != "initial-audit" || c.AccessKeyID != original.AccessKeyID || c.SecretAccessKey != original.SecretAccessKey {
		t.Fatal("stored initial writer not reused", err)
	}
	for _, mode := range []string{"no-state-material", "no-installation", "no-request", "expired", "external-session", "foreign-key-format"} {
		t.Run(mode, func(t *testing.T) {
			changed := state
			material := *state.Material
			changed.Material = &material
			switch mode {
			case "no-state-material":
				changed.Material = nil
			case "no-installation":
				changed.InstallationID = ""
			case "no-request":
				changed.RequestID = ""
			case "expired":
				changed.Material.StorageUseUntil = now
			case "external-session":
				changed.Material.Storage.SessionToken = "another-provider-session"
			case "foreign-key-format":
				changed.Material.Storage.AccessKeyID = "another-provider-key"
			}
			if _, err := initialSeaweedCredential(changed, now); err == nil {
				t.Fatal("non-original or expired writer accepted")
			}
		})
	}
}

type initialSeaweedNamedFailure struct{}

func (initialSeaweedNamedFailure) Error() string     { return "private provider detail must not appear" }
func (initialSeaweedNamedFailure) FixedStep() string { return "setup-policy-final" }

func TestInitialSeaweedDiagnosticNamesOwnedStageWithoutProviderDetails(t *testing.T) {
	err := initialSeaweedAt("bucket", initialSeaweedNamedFailure{})
	diagnostic := InitialPreparationRemedy(err)
	if !strings.Contains(diagnostic, "bucket/setup-policy-final") || strings.Contains(diagnostic, "private provider detail") {
		t.Fatal("lost fixed boundary or exposed provider content", diagnostic)
	}
	diagnostic = InitialPreparationRemedy(initialSeaweedAt("bucket", errors.New("private raw response")))
	if strings.Contains(diagnostic, "private raw response") {
		t.Fatal("raw provider response leaked")
	}
}
