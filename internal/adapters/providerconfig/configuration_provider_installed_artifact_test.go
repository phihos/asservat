package providerconfig

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestConfigurationInstalledArtifactRequiresVersionsWithoutLegacyFallback(t *testing.T) {
	in, selection, account, now := configurationProviderRecipeFixture(t)
	r, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil {
		t.Fatal(err)
	}
	// This is a pure public recipe fixture, not a completed resource receipt or
	// current proof. The real publisher validates those independent boundaries.
	in.ProviderAuthentication = &r.Profile
	in.ProviderInputs = &contracts.ConfigurationWorkerInputProvenance{OperationID: "70000000-0000-4000-8000-000000000001"}
	in.Activation = &contracts.HubWorkerRuntimeActivation{WorkerLayout: contracts.HubWorkerProviderInstalledLayout}
	b, err := ConfigurationProviderInstalledSetupArtifact(in, selection, account, now)
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		Format       string `json:"format"`
		AuditStorage struct {
			Prefixes                         []string `json:"prefixes"`
			Operations, DeniedOperations     []string
			Versioning                       string `json:"versioning"`
			NonNullVersions, PinnedReads     bool
			Accounting, BackendQualification string
		} `json:"auditStorage"`
	}
	if json.Unmarshal(b, &value) != nil || value.Format != "asservat-configuration-provider-installed-setup/v3" ||
		!slices.Equal(value.AuditStorage.Prefixes, []string{"hub-owner-configuration/v1/" + in.InstallationID + "/" + in.ClusterID + "/" + in.OwnerSource.UID + "/", "authority/v1/", "retention-acceptance/v1/", "lifecycle/v1/"}) ||
		!slices.Equal(value.AuditStorage.Operations, []string{"PutObject", "GetObject", "GetObjectVersion"}) ||
		!slices.Equal(value.AuditStorage.DeniedOperations, []string{"DeleteObject", "DeleteObjectVersion", "PutBucketVersioning", "PutBucketPolicy", "PutLifecycleConfiguration"}) ||
		value.AuditStorage.Versioning != "Enabled" || !value.AuditStorage.NonNullVersions || !value.AuditStorage.PinnedReads ||
		value.AuditStorage.Accounting != "every-attempt-and-version" || value.AuditStorage.BackendQualification != "required" {
		t.Fatal("fresh artifact lost fixed versioned backend requirements")
	}
	if bytes.Contains(b, []byte(`"conditionalCreate"`)) || bytes.Contains(b, []byte(`"noOverwriteDelete"`)) {
		t.Fatal("new artifact promised unsupported legacy capability")
	}
	in.Activation.WorkerLayout = contracts.HubWorkerInstalledLayout
	if _, err := ConfigurationProviderInstalledSetupArtifact(in, selection, account, now); err == nil {
		t.Fatal("legacy profile selected versioned artifact")
	}
	in.Activation.WorkerLayout = contracts.HubWorkerProviderInstalledLayout
	in.ProviderInputs = nil
	if _, err := ConfigurationProviderInstalledSetupArtifact(in, selection, account, now); err == nil {
		t.Fatal("missing original input provenance")
	}
}
