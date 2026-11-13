package bootstrap

import (
	"bytes"
	"encoding/json"

	"asservat.local/asservat/internal/adapters/postgres"
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

func initialSeaweedBundledIdentity(issued time.Time) contracts.BundledInitialProviderIdentity {
	return contracts.BundledInitialProviderIdentity{Format: contracts.BundledInitialProviderIdentityFormat, BackendName: "trial", Namespace: contracts.WorkerObjectReference{Name: "bootstrap", UID: "10000000-0000-4000-8000-000000000003"}, SetupAccount: contracts.WorkerObjectReference{Name: "trial-setup", UID: "10000000-0000-4000-8000-000000000004"}, EntityID: "10000000-0000-4000-8000-000000000005", SetupParent: contracts.InitialProviderParent{Accessor: "synthetic-original-setup", IssuedAt: issued, ExpiresAt: issued.Add(5 * time.Minute)}}
}

// Exercise the actual random-credential producer, closed retained-material
// codec and PostgreSQL credential binder used by initial_preparer_sql.go.
// These are synthetic values, not a SQL provision/admission authority fixture.
func TestInitialSeaweedGeneratedResourceUseCoversOriginalSQLBinding(t *testing.T) {
	issued := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Minute)
	selected := initialSeaweedBundledIdentity(issued)
	material := contracts.InitialBootstrapMaterial{Format: contracts.InitialBootstrapMaterialFormat, SetupToken: "synthetic-original-setup-token", BundledIdentity: &selected}
	if err := generateInitialSeaweedStorage(&material); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	retained, err := contracts.DecodeInitialBootstrapMaterial(bytes.NewReader(raw))
	if err != nil {
		t.Fatal("closed original material", err)
	}
	const installation = "10000000-0000-4000-8000-000000000001"
	const request = "10000000-0000-4000-8000-000000000002"
	sqlMaterial, err := postgres.NewInitialSQLMaterial(installation, request)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := issued.Add(2 * time.Minute)
	credentials, err := postgres.BindInitialSQLMaterial(sqlMaterial, installation, request, notBefore, notBefore.Add(15*time.Minute))
	if err != nil {
		t.Fatal("actual original SQL credential binding", err)
	}
	// This is the real provider consumer's required resource-use relationship.
	// The key provider's shorter original authority is a separate bound.
	if retained.StorageUseUntil.Before(credentials.NotAfter) {
		t.Fatal("generated initial storage resource-use ends before actual SQL binding")
	}
	if retained.StorageUseUntil != issued.Add(30*time.Minute) || retained.BundledIdentity == nil || *retained.BundledIdentity != selected || retained.BundledIdentity.SetupParent.ExpiresAt != issued.Add(5*time.Minute) {
		t.Fatal("resource declaration renewed or changed original KMS identity bounds")
	}
	state := contracts.InitialBootstrapState{InstallationID: installation, RequestID: request, Material: &retained}
	if _, err = initialSeaweedCredential(state, notBefore); err != nil {
		t.Fatal("stored generated writer consumer", err)
	}
	// Retrying the first-material generator cannot replace acknowledged keys or
	// lengthen either retained interval. No new clock or credential is selected.
	if err = generateInitialSeaweedStorage(&retained); err == nil {
		t.Fatal("retained writer regenerated")
	}
	after, _ := json.Marshal(retained)
	defer clear(after)
	if !bytes.Equal(raw, after) {
		t.Fatal("retry changed original private material or interval")
	}
}

func TestInitialSeaweedGenerationPreservesDeclaredUseAndRequiresOriginalZeroBoundSource(t *testing.T) {
	issued := time.Now().UTC().Truncate(time.Second)
	selected := initialSeaweedBundledIdentity(issued)
	until := issued.Add(time.Hour + 123*time.Microsecond)
	for _, bundled := range []bool{false, true} {
		material := contracts.InitialBootstrapMaterial{StorageUseUntil: until}
		if bundled {
			copy := selected
			material.BundledIdentity = &copy
		}
		if err := generateInitialSeaweedStorage(&material); err != nil || material.StorageUseUntil != until {
			t.Fatal("declared mixed/external interval changed", err)
		}
	}
	for _, mode := range []string{"missing-identity", "invalid-identity"} {
		t.Run(mode, func(t *testing.T) {
			material := contracts.InitialBootstrapMaterial{}
			if mode == "invalid-identity" {
				changed := selected
				changed.SetupParent.Accessor = ""
				material.BundledIdentity = &changed
			}
			if err := generateInitialSeaweedStorage(&material); err == nil || !material.StorageUseUntil.IsZero() || material.Storage != (contracts.OwnerStorageCredential{}) {
				t.Fatal("unbound missing declaration generated or adopted material")
			}
		})
	}
}
