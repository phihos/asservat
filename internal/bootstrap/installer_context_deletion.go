package bootstrap

import (
	"context"
	"strconv"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// contextDeletionEnabled: an installation deletes expired context evidence
// exactly when its publisher, and with it the evidence store, is installed
// (ADR-205 decision 7).
func (k *InstallerContinuation) contextDeletionEnabled() bool {
	return k.publisherEnabled()
}

// contextDeletionSigning is the deletion signing Transit key on the
// configuration audit mount (ADR-205 decision 6), or zero without deletion.
// Like the worker configuration audit key it binds the resource journal
// through the provider selection, so the mount comes from the original
// preparation services.
func (k *InstallerContinuation) contextDeletionSigning() (contracts.OwnerPublicTransit, error) {
	if !k.contextDeletionEnabled() {
		return contracts.OwnerPublicTransit{}, nil
	}
	s := k.plan.Services
	if s == nil || s.KeyService.AuditMount == "" {
		return contracts.OwnerPublicTransit{}, mounts.ErrUnavailable
	}
	return contracts.OwnerPublicTransit{Mount: s.KeyService.AuditMount, Key: contracts.ContextDeletionSigningKeyName(k.record.Scope.InstallationID)}, nil
}

// contextDeletionSetup is the phase-3 artifact's evidence store for the
// operator's delete credential, or nil without deletion.
func (k *InstallerContinuation) contextDeletionSetup() *contracts.InstallerEvidenceStore {
	if !k.contextDeletionEnabled() {
		return nil
	}
	return k.input.Public.Federation.EvidenceStore
}

// ContextDeletionCredentials stores the operator's evidence delete credential
// in its immutable Secret and reads the deletion signing key back through
// the phase-3 inspection token; the capacity projection then pins the
// evidence store and that key (ADR-205 decisions 4 and 6).
func (k *InstallerContinuation) ContextDeletionCredentials(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, inbox kube.InstallerInbox, inspector *providerconfig.SetupReader, owner contracts.OwnerDeployment) error {
	store := k.contextDeletionSetup()
	if store == nil {
		return nil
	}
	if !validEvidenceDeleteCredential(inbox.EvidenceDeleteCredential) {
		return mounts.ErrUnavailable
	}
	k.at("deletion/credential")
	if err := kube.EnsureEvidenceDeleteSecret(ctx, k.in.kubernetes("administrator-token"), inventory.Namespace.Name, k.record.Scope.InstallationID, inbox.EvidenceDeleteCredential); err != nil {
		return err
	}
	k.at("deletion/verify")
	signing, err := k.contextDeletionSigning()
	if err != nil {
		return err
	}
	if signing.Mount != owner.KeyService.AuditMount {
		return mounts.ErrUnavailable
	}
	readback, err := inspector.ReadContextDeletionSigning(ctx, contracts.OwnerProviderEndpoint{Endpoint: owner.KeyService.Endpoint, Roots: owner.KeyService.Roots}, signing.Mount, signing.Key)
	if err != nil {
		return err
	}
	roots, err := providerconfig.TrustRootsPEM([]byte(store.RootsPEM), time.Now())
	if err != nil {
		return err
	}
	section := contracts.ContextDeletionDeployment{EvidenceStore: contracts.OwnerAuditStore{Endpoint: store.Endpoint, Roots: roots, Region: store.Region, Bucket: store.Bucket},
		Signing: contracts.ContextDeletionSigning{Mount: readback.Mount, Key: readback.Key, Version: readback.Version, KeyID: contextDeletionKeyID(readback.Version), PublicKeys: map[string][]byte{}}}
	for version, key := range readback.PublicKeys {
		section.Signing.PublicKeys[contextDeletionKeyID(version)] = key
	}
	if !kube.ContextDeletionSectionValid(&section, time.Now()) {
		return mounts.ErrUnavailable
	}
	k.contextDeletion = &section
	return nil
}

// contextDeletionKeyID names a Transit key version in the deletion record's
// JWS header.
func contextDeletionKeyID(version int) string { return "v" + strconv.Itoa(version) }
