package bootstrap

import (
	"bytes"
	"context"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// Public audit retirement is needed even without an evidence publisher. It
// shares the existing hub-worker cleanup task and its three cold facet pools.
func (k *InstallerContinuation) operationCleanupEnabled() bool {
	return k != nil && k.input.Public != nil && k.input.Public.Capacity != nil
}

// OperationCleanupProjection publishes actual acknowledged role/capacity
// receipts, operator-provided storage credentials and observed signing keys.
// It neither provisions storage IAM nor turns configuration equality into
// authority for a historical row with a different original store or key.
func (k *InstallerContinuation) OperationCleanupProjection(ctx context.Context, resources *kube.InitialRuntimeResources, bridge *kube.InitialRuntimeBridge, inbox kube.InstallerInbox, inspector *providerconfig.SetupReader, owner contracts.OwnerDeployment) error {
	if !k.operationCleanupEnabled() {
		if len(inbox.CleanupAuditCredential) != 0 || len(inbox.CleanupVerifyCredential) != 0 {
			return mounts.ErrUnavailable
		}
		return nil
	}
	if k.capacity == nil || k.publicRoot == nil || k.publicRoles == nil || inspector == nil {
		return mounts.ErrUnavailable
	}
	cleanup, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(inbox.CleanupAuditCredential))
	if err != nil {
		return mounts.ErrUnavailable
	}
	verify, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(inbox.CleanupVerifyCredential))
	if err != nil || cleanup.AccessKeyID == "" || cleanup.SecretAccessKey == "" || verify.AccessKeyID == "" || verify.SecretAccessKey == "" || cleanup.AccessKeyID == verify.AccessKeyID {
		return mounts.ErrUnavailable
	}
	k.at("operation-cleanup/signing")
	signing, err := k.contextDeletionSigning()
	if err != nil || signing.Mount != owner.KeyService.AuditMount {
		return mounts.ErrUnavailable
	}
	observed, err := inspector.ReadContextDeletionSigning(ctx, contracts.OwnerProviderEndpoint{Endpoint: owner.KeyService.Endpoint, Roots: owner.KeyService.Roots}, signing.Mount, signing.Key)
	if err != nil {
		return err
	}
	sign := contracts.CaptureCleanupSigning{Mount: observed.Mount, Name: observed.Key, Version: observed.Version, KeyID: contextDeletionKeyID(observed.Version), PublicKeys: map[string][]byte{}}
	for version, key := range observed.PublicKeys {
		sign.PublicKeys[contextDeletionKeyID(version)] = append([]byte(nil), key...)
	}
	backing := k.capacity.qualification.RootBacking
	store := backing.Capture.Policy.StoreID
	if backing.Normal.Policy.StoreID != store || backing.Resolution.Policy.StoreID != store || owner.PermissionRootID != backing.RootID {
		return mounts.ErrUnavailable
	}
	sql := owner.Postgres
	sql.MaxConnections = 1
	deployment := contracts.CaptureCleanupDeployment{Format: contracts.CaptureCleanupDeploymentFormat, InstallationID: k.record.Scope.InstallationID, RootID: owner.PermissionRootID, StoreID: store,
		Postgres: sql, AuditStore: owner.AuditStore, KeyService: contracts.ConfigurationKeyService{Endpoint: owner.KeyService.Endpoint, Roots: owner.KeyService.Roots, AuditMount: owner.KeyService.AuditMount, AuditKey: owner.KeyService.AuditKey}, Signing: sign}
	var projection *kube.CaptureCleanupProjection
	k.at("operation-cleanup/projection")
	return converge(ctx, time.Minute, func() error {
		return k.publicRoot.WithPublicRoleOperation(ctx, func(op context.Context) error {
			verified, err := k.publicRoles.Verify(op)
			if err != nil {
				return err
			}
			if projection == nil {
				deployment.RoleRootUID, deployment.RoleSetupID = verified.UID, verified.State.OperationID
				projection, err = kube.NewCaptureCleanupProjection(bridge, resources, k.publicRoot, deployment, kube.CaptureCleanupProviderMaterial{Cleanup: cleanup, Verify: verify})
				if err != nil {
					return err
				}
			}
			_, err = projection.Publish(op, verified)
			return err
		})
	})
}
