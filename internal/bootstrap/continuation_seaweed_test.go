package bootstrap

import (
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"github.com/google/uuid"
)

func TestContinuationSeaweedWorkerGrantUsesOriginalRecipe(t *testing.T) {
	roles, _, in := configurationRoleInputPair(t)
	account := roles.Roles.ServiceAccount
	account.Name = "asservat-" + strings.ReplaceAll(in.InstallationID, "-", "") + "-worker"
	selection := contracts.ConfigurationProviderSelection{AuthMount: "kubernetes", AuthMountAccessor: "auth_kubernetes_1",
		AuditCredentials:         contracts.WorkerObjectReference{Name: "asservat-" + strings.ReplaceAll(in.InstallationID, "-", "") + "-worker-providers", UID: uuid.NewString()},
		WorkerConfigurationAudit: contracts.OwnerPublicTransit{Mount: in.KeyService.AuditMount, Key: "worker-audit"},
		ContextDeletionSigning:   contracts.OwnerPublicTransit{Mount: in.KeyService.AuditMount, Key: contracts.ContextDeletionSigningKeyName(in.InstallationID)},
		CleanupAudit:             contracts.OwnerPublicTransit{Mount: in.KeyService.AuditMount, Key: in.KeyService.AuditKey}}
	credential, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "configuration-audit", ScopeID: in.InstallationID})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := workerSeaweedGrant(in, selection, account, contracts.HubWorkerProviderInstalledLayout, credential, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"hub-owner-configuration/v1/" + in.InstallationID + "/" + in.ClusterID + "/" + in.OwnerSource.UID + "/", "authority/v1/", "retention-acceptance/v1/", "lifecycle/v1/", "download-worker-configuration/v1/" + in.InstallationID + "/", "context-deletion/v1/"}
	if grant.InstallationID != in.InstallationID || grant.ClusterID != in.ClusterID || grant.SourceUID != in.OwnerSource.UID || grant.Credential != credential || !slices.Equal(grant.Prefixes, expected) {
		t.Fatal("worker grant diverged from original recipe")
	}
	admin, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "admin", ScopeID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "initial-audit", ScopeID: in.InstallationID})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := providerconfig.CompileSeaweedStorage(admin, []contracts.SeaweedGrant{{Credential: initial, Bucket: in.AuditStore.Bucket, InstallationID: in.InstallationID}, grant})
	if err != nil {
		t.Fatal("actual IAM compiler rejected existing worker recipe", err)
	}
	defer clear(compiled.Config)
	for _, mode := range []string{"principal", "installation", "layout"} {
		t.Run(mode, func(t *testing.T) {
			c := credential
			layout := contracts.HubWorkerProviderInstalledLayout
			switch mode {
			case "principal":
				c.Principal.Purpose = "owner-audit"
			case "installation":
				c.Principal.ScopeID = uuid.NewString()
			case "layout":
				layout = "unknown"
			}
			if _, err := workerSeaweedGrant(in, selection, account, layout, c, time.Now()); err == nil {
				t.Fatal("foreign worker scope accepted")
			}
		})
	}
}

func TestContinuationSeaweedExternalHasNoProviderEffects(t *testing.T) {
	k := &InstallerContinuation{}
	if err := k.prepareSmallWorkerStore(nil, contracts.HubWorkerDeployment{}, contracts.ConfigurationProviderSelection{}, contracts.WorkerObjectReference{}, ""); err != nil {
		t.Fatal("external path invoked bundled provider")
	}
}
