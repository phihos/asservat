package providerconfig

import (
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

type configurationProviderSetupRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
}

// ConfigurationProviderSetupArtifact is a single public automation artifact.
// It applies nothing and contains no administrator/runtime credentials. The
// standard provider operator applies its exact requests; the actual installer
// separately verifies current provider readback and protected original scope.
func ConfigurationProviderSetupArtifact(in contracts.HubWorkerDeployment, selection contracts.ConfigurationProviderSelection, account contracts.WorkerObjectReference, now time.Time) ([]byte, error) {
	return configurationProviderSetupArtifact(in, selection, account, now, false)
}

// ConfigurationProviderInstalledSetupArtifact is the fresh worker2 recipe.
// Non-null versions are intrinsic to that closed profile, not a selected flag.
// It still requires independently qualified IAM, accounting and recovery; this
// artifact never changes the backend or grants installation authority.
func ConfigurationProviderInstalledSetupArtifact(in contracts.HubWorkerDeployment, selection contracts.ConfigurationProviderSelection, account contracts.WorkerObjectReference, now time.Time) ([]byte, error) {
	if in.Activation == nil || in.Activation.WorkerLayout != contracts.HubWorkerProviderInstalledLayout || in.ProviderInputs == nil || in.ProviderAuthentication == nil || ValidateConfigurationProviderAuthentication(in, *in.ProviderAuthentication, now) != nil ||
		in.ProviderAuthentication.AuthMount != selection.AuthMount || in.ProviderAuthentication.AuthMountAccessor != selection.AuthMountAccessor || in.ProviderAuthentication.AuditCredentials != selection.AuditCredentials || in.ProviderAuthentication.ServiceAccount != account {
		return nil, cfg.ErrInvalid
	}
	return configurationProviderSetupArtifact(in, selection, account, now, true)
}

// ConfigurationProviderPairSetupArtifact is the fresh provider pair's worker2
// artifact before its inputs exist (the ADR-183 phase-1 outbox). The original
// journal's worker layout alone selects the installed v2 storage requirements.
func ConfigurationProviderPairSetupArtifact(in contracts.HubWorkerDeployment, selection contracts.ConfigurationProviderSelection, account contracts.WorkerObjectReference, layout string, now time.Time) ([]byte, error) {
	if layout != contracts.HubWorkerProviderInstalledLayout {
		return nil, cfg.ErrInvalid
	}
	return configurationProviderSetupArtifact(in, selection, account, now, true)
}

func configurationProviderSetupArtifact(in contracts.HubWorkerDeployment, selection contracts.ConfigurationProviderSelection, account contracts.WorkerObjectReference, now time.Time, versioned bool) ([]byte, error) {
	r, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil {
		return nil, err
	}
	body, err := configurationProviderRecipeBody(in, r)
	if err != nil {
		return nil, err
	}
	var requests [4]configurationProviderSetupRequest
	reads := []string{"sys/mounts/auth/" + selection.AuthMount, "auth/" + selection.AuthMount + "/config", "sys/mounts/" + in.KeyService.AuditMount, in.KeyService.AuditMount + "/keys/" + in.KeyService.AuditKey}
	for i, role := range r.Roles {
		policy, e := ownerProviderCanonical(struct {
			Policy string `json:"policy"`
		}{string(role.Policy)})
		if e != nil {
			return nil, e
		}
		policyPath := "sys/policies/acl/" + role.Name
		rolePath := "auth/" + selection.AuthMount + "/role/" + role.Name
		requests[2*i] = configurationProviderSetupRequest{Method: "POST", Path: policyPath, Body: policy}
		requests[2*i+1] = configurationProviderSetupRequest{Method: "POST", Path: rolePath, Body: role.Role}
		reads = append(reads, policyPath, rolePath)
	}
	// Native backend qualification must establish the actual conditional-create
	// and no-overwrite/delete semantics. These requirements neither create IAM
	// nor pretend every S3-compatible provider implements AWS condition keys.
	// ADR-189: the same audit-only principal also writes the permission
	// authority records. Their root is minted after this phase, so the scope
	// is the fixed authority prefix; the writer admits only its own root.
	storage := struct {
		Prefixes             []string `json:"prefixes"`
		Operations           []string `json:"operations"`
		ConditionalCreate    bool     `json:"conditionalCreate"`
		NoOverwriteDelete    bool     `json:"noOverwriteDelete"`
		BackendQualification string   `json:"backendQualification"`
	}{[]string{"hub-owner-configuration/v1/" + in.InstallationID + "/" + in.ClusterID + "/" + in.OwnerSource.UID + "/", "authority/v1/"},
		[]string{"PutObject", "GetObject"}, true, true, "required"}
	var requirements any = storage
	format := "asservat-configuration-provider-setup/v1"
	if versioned {
		// ADR-195: the hub retention source's checkpoint and lifecycle audits.
		format = "asservat-configuration-provider-installed-setup/v3"
		requirements = struct {
			Prefixes             []string `json:"prefixes"`
			Operations           []string `json:"operations"`
			DeniedOperations     []string `json:"deniedOperations"`
			Versioning           string   `json:"versioning"`
			NonNullVersions      bool     `json:"nonNullVersions"`
			PinnedReads          bool     `json:"pinnedReads"`
			Accounting           string   `json:"accounting"`
			BackendQualification string   `json:"backendQualification"`
		}{append(storage.Prefixes, "retention-acceptance/v1/", "lifecycle/v1/"),
			[]string{"PutObject", "GetObject", "GetObjectVersion"},
			[]string{"DeleteObject", "DeleteObjectVersion", "PutBucketVersioning", "PutBucketPolicy", "PutLifecycleConfiguration"},
			"Enabled", true, true, "every-attempt-and-version", "required"}
	}
	return ownerProviderCanonical(struct {
		Format       string                               `json:"format"`
		Recipe       json.RawMessage                      `json:"recipe"`
		Apply        [4]configurationProviderSetupRequest `json:"apply"`
		Inspect      []string                             `json:"inspect"`
		AuditStorage any                                  `json:"auditStorage"`
	}{format, body, requests, reads, requirements})
}
