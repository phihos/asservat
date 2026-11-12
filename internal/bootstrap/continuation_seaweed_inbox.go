package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

func seaweedInboxCredential(raw []byte, purpose, installation string) (contracts.SeaweedCredential, error) {
	var zero contracts.SeaweedCredential
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(raw))
	if err != nil || c.SessionToken != "" {
		return zero, mounts.ErrUnavailable
	}
	out := contracts.SeaweedCredential{Principal: contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: installation}, AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey}
	if providerconfig.ValidateSeaweedCredential(out) != nil {
		return zero, mounts.ErrUnavailable
	}
	return out, nil
}

func newSeaweedInboxCredential(purpose, installation string) ([]byte, error) {
	c, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: installation})
	if err != nil {
		return nil, err
	}
	v, err := providerconfig.SeaweedRuntimeCredential(c)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (k *InstallerContinuation) retainedWorkerStoreGrant(ctx context.Context, resources *kube.InitialRuntimeResources, inventory kube.InitialRuntimeResourceInventory) (contracts.SeaweedGrant, error) {
	var zero contracts.SeaweedGrant
	snapshot, err := resources.Read(ctx)
	if err != nil || snapshot.State.WorkerProvider == nil || snapshot.State.WorkerInputs == nil || snapshot.State.WorkerInputs.Receipt == nil {
		return zero, mounts.ErrUnavailable
	}
	docs, err := BuildInitialConfigurationDocuments(resources.Initial(), inventory, k.record.Claim.ID)
	if err != nil {
		return zero, err
	}
	worker, err := contracts.DecodeHubWorkerDeployment(bytes.NewReader(docs.Worker))
	if err != nil {
		return zero, err
	}
	selection := *snapshot.State.WorkerProvider
	credential, err := kube.ReadOrInitializeSeaweedCredential(ctx, k.in.kubernetes("administrator-token"), worker.Namespace.Name, selection.AuditCredentials, contracts.ConfigurationProviderAuditCredentialFile, contracts.SeaweedPrincipalKey{Purpose: "configuration-audit", ScopeID: worker.InstallationID})
	if err != nil {
		return zero, err
	}
	return workerSeaweedGrant(worker, selection, inventory.WorkerAccount, snapshot.State.WorkerLayout, credential, time.Now())
}

// The existing phase-3 inbox retains every generated candidate before IAM
// enablement. Retrying recovers the original winner; inspection refresh changes
// only its short-lived token. No scoped storage key is regenerated in place.
func (k *InstallerContinuation) ownerProviderInbox(ctx context.Context, resources *kube.InitialRuntimeResources, inventory kube.InitialRuntimeResourceInventory, owner contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, artifact []byte, serving contracts.InstallerServingTLSPlan) (kube.InstallerInbox, error) {
	var zero kube.InstallerInbox
	if k.keyService != nil && k.objectStore == nil {
		return k.mixedOwnerProviderInbox(ctx, artifact)
	}
	if k.keyService == nil && k.objectStore == nil {
		return k.awaitInbox(ctx, 3)
	}
	data, err := k.smallOwnerMaterial(ctx, serving)
	if err != nil {
		return zero, err
	}
	if data == nil {
		data = map[string][]byte{}
	}
	defer func() {
		for _, raw := range data {
			clear(raw)
		}
	}()
	data[contracts.InstallerInboxPhase] = []byte("3")
	selected := map[string]string{contracts.InstallerInboxAuditCredential: "owner-audit"}
	if k.federation != nil {
		selected[contracts.InstallerInboxFederationAuditCredential] = "federation-audit"
	}
	if k.publisher != nil {
		selected[contracts.InstallerInboxPublisherAuditCredential] = "publisher-audit"
		selected[contracts.InstallerInboxEvidenceReadCredential] = "publisher-read"
	}
	if k.downloads != nil {
		selected[contracts.InstallerInboxDownloadEvidenceCredential] = "download-read"
	}
	if k.contextDeletionSetup() != nil {
		selected[contracts.InstallerInboxEvidenceDeleteCredential] = "evidence-delete"
	}
	if k.operationCleanupEnabled() {
		selected[contracts.InstallerInboxCleanupAuditCredential] = "operation-cleanup"
		selected[contracts.InstallerInboxCleanupVerifyCredential] = "operation-verify"
	}
	for key, purpose := range selected {
		data[key], err = newSeaweedInboxCredential(purpose, owner.InstallationID)
		if err != nil {
			return zero, err
		}
	}
	digest := sha256.Sum256(artifact)
	recipe := hex.EncodeToString(digest[:])
	admin := k.in.kubernetes("administrator-token")
	var original *core.Secret
	if k.keyService == nil {
		original, err = kube.ReadOrCreateMixedInstallerInbox(ctx, admin, k.input.Namespace, owner.InstallationID, recipe, contracts.InstallerProviderBundledObjectStore, data)
	} else {
		original, err = kube.ReadOrCreateBundledInstallerInbox(ctx, admin, k.input.Namespace, owner.InstallationID, recipe, data)
	}
	if err != nil {
		return zero, err
	}
	defer func() {
		for _, raw := range original.Data {
			clear(raw)
		}
	}()
	// Storage keys recover the retained winner. Private TLS/client material
	// must still match the source that was actually checked in this operation.
	// A changed source cannot make an older unchecked carrier current.
	for key, raw := range data {
		if _, storage := selected[key]; !storage && !bytes.Equal(original.Data[key], raw) {
			return zero, &fixedStepError{"owner-material/original-source", mounts.ErrUnavailable}
		}
	}
	var credentials continuationSeaweedOwnerCredentials
	for key, target := range map[string]*contracts.SeaweedCredential{
		contracts.InstallerInboxAuditCredential: &credentials.Owner, contracts.InstallerInboxFederationAuditCredential: &credentials.Federation,
		contracts.InstallerInboxPublisherAuditCredential: &credentials.PublisherAudit, contracts.InstallerInboxEvidenceReadCredential: &credentials.PublisherRead,
		contracts.InstallerInboxDownloadEvidenceCredential: &credentials.DownloadRead, contracts.InstallerInboxEvidenceDeleteCredential: &credentials.EvidenceDelete,
		contracts.InstallerInboxCleanupAuditCredential: &credentials.Cleanup, contracts.InstallerInboxCleanupVerifyCredential: &credentials.Verify,
	} {
		if purpose, enabled := selected[key]; enabled {
			*target, err = seaweedInboxCredential(original.Data[key], purpose, owner.InstallationID)
			if err != nil {
				return zero, err
			}
		}
	}
	worker, err := k.retainedWorkerStoreGrant(ctx, resources, inventory)
	if err != nil {
		return zero, err
	}
	grants, err := ownerSeaweedGrants(continuationSeaweedOwnerInput{Store: k.plan.Services.AuditStore, Owner: owner, Profile: profile, Artifact: artifact, Worker: worker, Credentials: credentials, Federation: k.federation, Publisher: k.publisherSetup(), Downloads: k.downloadEvidenceSetup(), Deletion: k.contextDeletionSetup(), Cleanup: k.operationCleanupEnabled(), Now: time.Now()})
	if err != nil {
		return zero, err
	}
	store, err := k.openSmallStore(ctx)
	if err != nil {
		return zero, err
	}
	defer store.Close()
	if err := store.enable(ctx, grants); err != nil {
		return zero, err
	}
	if k.keyService == nil {
		return k.awaitMixedProviderInbox(ctx, 3, recipe, contracts.InstallerProviderBundledObjectStore)
	}
	token, err := k.applySmallProvider(ctx, 3, artifact)
	if err != nil {
		return zero, err
	}
	defer clear(token)
	if _, err := kube.CompleteBundledInstallerInbox(ctx, admin, k.input.Namespace, owner.InstallationID, recipe, original, token); err != nil {
		return zero, err
	}
	return kube.ReadInstallerInbox(ctx, admin, k.input.Namespace, owner.InstallationID, 3)
}
