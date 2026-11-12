package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestInitialBootstrapMixedProviderInputNeedsOnlyExternalCredentials(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	until := now.Add(time.Minute)
	storage := contracts.OwnerStorageCredential{AccessKeyID: "external-access", SecretAccessKey: "external-private"}
	for _, test := range []struct {
		name     string
		services initialBootstrapServices
		fragment contracts.InitialBootstrapProviderInput
	}{
		{"external-both", initialBootstrapServices{}, contracts.InitialBootstrapProviderInput{Format: contracts.InitialBootstrapMaterialFormat, IssuerToken: "external-issuer", Storage: &storage, StorageUseUntil: until}},
		{"external-key-bundled-store", initialBootstrapServices{ObjectStore: &contracts.SmallSeaweedPlan{}}, contracts.InitialBootstrapProviderInput{Format: contracts.InitialBootstrapMaterialFormat, IssuerToken: "external-issuer", StorageUseUntil: until}},
		{"bundled-key-external-store", initialBootstrapServices{KeyService: &contracts.SmallOpenBaoPlan{}}, contracts.InitialBootstrapProviderInput{Format: contracts.InitialBootstrapMaterialFormat, Storage: &storage, StorageUseUntil: until}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.fragment)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := contracts.DecodeInitialBootstrapProviderInput(strings.NewReader(string(raw)))
			if err != nil {
				t.Fatal("closed operator fragment rejected", err)
			}
			got, err := initialProviderFragmentMaterial(decoded, test.services, now)
			if err != nil || !got.StorageUseUntil.Equal(until) || got.IssuerToken != test.fragment.IssuerToken {
				t.Fatal("mixed fragment requires fake selected-side credential", err)
			}
			if test.services.ObjectStore != nil && got.Storage != (contracts.OwnerStorageCredential{}) {
				t.Fatal("selected store retained supplied credential")
			}
		})
	}
}
func TestInitialBootstrapMalformedExternalFragmentRefusesBeforeSelectedEffects(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, raw := range []string{
		`{"format":"asservat-initial-bootstrap-material/v1"}`,
		`{"format":"asservat-initial-bootstrap-material/v1","storage":{"accessKeyID":"access","secretAccessKey":"secret","sessionToken":""}}`,
		`{"format":"asservat-initial-bootstrap-material/v1","storageUseUntil":"2020-01-01T00:00:00Z"}`,
		`{"format":"asservat-initial-bootstrap-material/v1","setupToken":"forbidden"}`,
		`{"format":"asservat-initial-bootstrap-material/v1","registryConfig":"forbidden"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "provider-material.json"), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			input, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			// No provider inputs exist: reaching the selected setup helper would
			// dereference absent native inputs. Invalid external fields must stop
			// before that helper, login, key generation or any provider effect.
			d := &initialBootstrapProcess{services: initialBootstrapServices{KeyService: &contracts.SmallOpenBaoPlan{}}}
			if _, err = d.firstMaterial(t.Context(), input); err == nil {
				t.Fatal("invalid external fragment accepted")
			}
		})
	}
	fragment := contracts.InitialBootstrapProviderInput{Format: contracts.InitialBootstrapMaterialFormat, IssuerToken: "unused-issuer", StorageUseUntil: now.Add(time.Minute)}
	if _, err := initialProviderFragmentMaterial(fragment, initialBootstrapServices{KeyService: &contracts.SmallOpenBaoPlan{}}, now); err == nil {
		t.Fatal("missing external storage hidden by bundled key selection")
	}
}
func TestInitialBootstrapExternalKeyBundledStoreNormalizesOriginalFragment(t *testing.T) {
	until := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	fragment := contracts.InitialBootstrapProviderInput{Format: contracts.InitialBootstrapMaterialFormat, IssuerToken: "external-original-issuer", StorageUseUntil: until}
	raw, _ := json.Marshal(fragment)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "provider-material.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	d := &initialBootstrapProcess{services: initialBootstrapServices{ObjectStore: &contracts.SmallSeaweedPlan{}}}
	got, err := d.firstMaterial(t.Context(), input)
	if err != nil || got.IssuerToken != fragment.IssuerToken || got.Storage.AccessKeyID == "" || got.Storage.SecretAccessKey == "" || !got.StorageUseUntil.Equal(until) || got.BundledIdentity != nil {
		t.Fatal("actual first-material normalization failed", err)
	}
}
