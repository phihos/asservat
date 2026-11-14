package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

// These two independently provisioned storage credentials are private input
// to the installer, never a journal payload or public digest. The producer
// chooses no endpoint/key from a token and creates no provider authority.
type CaptureCleanupProviderMaterial struct {
	Cleanup, Verify contracts.OwnerStorageCredential
}

// One concrete producer owns its original first claim attempt. A failed or
// unknown claim response never turns a subsequent read of absence into a new
// CREATE grant. The original journal still serializes independent processes.
type CaptureCleanupProjection struct {
	bridge         *InitialRuntimeBridge
	resources      *InitialRuntimeResources
	roles          *PublicRuntimeRoleRoot
	deployment     contracts.CaptureCleanupDeployment
	provider       CaptureCleanupProviderMaterial
	claimAttempted bool // serialized by the original bridge operation
}

func NewCaptureCleanupProjection(bridge *InitialRuntimeBridge, resources *InitialRuntimeResources, root *PublicRuntimeRoleRoot, deployment contracts.CaptureCleanupDeployment, provider CaptureCleanupProviderMaterial) (*CaptureCleanupProjection, error) {
	if bridge == nil || resources == nil || root == nil || bridge.preparer != resources.preparer || bridge.rootUID != resources.rootUID ||
		!equalJSON(bridge.initial, resources.initial) || resources.workerLayout == "" || !initialRuntimeProviderSelectionValid(resources.initial.InstallationID, resources.workerLayout, resources.ownerLayout, resources.workerProvider, resources.ownerProvider) ||
		deployment.Format != contracts.CaptureCleanupDeploymentFormat || deployment.InstallationID != bridge.initial.InstallationID ||
		deployment.InstallationID != root.input.InstallationID || !reflect.DeepEqual(deployment.AuditStore, resources.initial.AuditStore) || !reflect.DeepEqual(deployment.KeyService, resources.initial.KeyService) || !publicRuntimeWorkerBindingValid(root.input) || resources.workerProvider == nil || resources.workerProvider.CleanupAudit == (contracts.OwnerPublicTransit{}) ||
		resources.workerProvider.CleanupAudit != (contracts.OwnerPublicTransit{Mount: deployment.KeyService.AuditMount, Key: deployment.KeyService.AuditKey}) ||
		resources.workerProvider.ContextDeletionSigning != (contracts.OwnerPublicTransit{Mount: deployment.Signing.Mount, Key: deployment.Signing.Name}) {
		return nil, cfg.ErrInvalid
	}
	raw, err := json.Marshal(deployment)
	var cloned contracts.CaptureCleanupDeployment
	if err != nil || len(raw) > contracts.CaptureCleanupDeploymentMaxBytes || json.Unmarshal(raw, &cloned) != nil {
		return nil, cfg.ErrInvalid
	}
	return &CaptureCleanupProjection{bridge: bridge, resources: resources, roles: root, deployment: cloned, provider: provider}, nil
}

func cleanupProjectionAnnotations(original contracts.PublicRuntimeWorkerBinding, claim *contracts.CaptureCleanupProjectionClaim) map[string]string {
	return map[string]string{"asservat.io/runtime-resource-uid": original.Resources.UID, "asservat.io/runtime-resource-setup": original.ResourceSetupID, "asservat.io/projection-id": claim.OperationID, "asservat.io/projection-public": claim.PublicDigest}
}

func (s *InitialRuntimeBridge) readCleanupProjection(ctx context.Context, original contracts.PublicRuntimeWorkerBinding, claim *contracts.CaptureCleanupProjectionClaim, data map[string][]byte) (contracts.CaptureCleanupProjectionReceipt, error) {
	var out contracts.CaptureCleanupProjectionReceipt
	name := contracts.HubWorkerCleanupProjectionName(s.initial.InstallationID)
	raw, err := s.preparer.creator.api.Get().AbsPath("/api/v1/namespaces/" + s.initial.Namespace.Name + "/secrets/" + name).MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return out, cfg.ErrUnavailable
	}
	defer clear(raw)
	var object core.Secret
	if len(raw) > 512<<10 || permissionJSON(raw, 512<<10, 32768) != nil || strictGuardJSON(raw, &object) != nil {
		return out, cfg.ErrChanged
	}
	defer clearRuntimeProjection(object.Data)
	if object.APIVersion != "v1" || object.Kind != "Secret" || object.Namespace != s.initial.Namespace.Name || object.Name != name ||
		!authorization.UUID(string(object.UID)) || !identity.Text(object.ResourceVersion, 128) || object.DeletionTimestamp != nil || object.Immutable == nil || !*object.Immutable || object.Type != core.SecretTypeOpaque ||
		len(object.Labels) != 0 || len(object.OwnerReferences) != 0 || len(object.Finalizers) != 0 || len(object.StringData) != 0 || !reflect.DeepEqual(object.Annotations, cleanupProjectionAnnotations(original, claim)) || len(object.Data) != len(data) || s.deadline(ctx) != nil {
		return out, cfg.ErrChanged
	}
	for key, want := range data {
		if !bytes.Equal(object.Data[key], want) {
			return out, cfg.ErrChanged
		}
	}
	out = contracts.CaptureCleanupProjectionReceipt{Secret: contracts.WorkerObjectReference{Name: name, UID: string(object.UID)}, ResourceVersion: object.ResourceVersion, ObservedAt: s.source.client.now().UTC().Truncate(time.Microsecond)}
	if claim.Receipt != nil {
		if claim.Receipt.Secret != out.Secret || claim.Receipt.ResourceVersion != out.ResourceVersion {
			return contracts.CaptureCleanupProjectionReceipt{}, cfg.ErrChanged
		}
		out = *claim.Receipt // Historical observation is never renewed on replay.
	}
	return out, nil
}

func (s *InitialRuntimeBridge) writeCleanupProjection(ctx context.Context, resources *InitialRuntimeResources, object *core.Secret, next contracts.InitialRuntimeResourceState) (contracts.InitialRuntimeResourceSnapshot, error) {
	var zero contracts.InitialRuntimeResourceSnapshot
	if object == nil || !resources.valid(next) || !s.source.client.now().Before(next.Until) || s.deadline(ctx) != nil {
		return zero, cfg.ErrUnavailable
	}
	original, err := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(object.Data["state.json"]))
	if err != nil || !resources.valid(original) || !cleanupProjectionTransition(original, next) {
		return zero, cfg.ErrChanged
	}
	if original.CleanupProjection == nil && !s.source.client.now().Before(next.CleanupProjection.Until) {
		return zero, cfg.ErrUnavailable
	}
	payload, err := json.Marshal(next)
	if err != nil || len(payload) > contracts.InitialRuntimeResourcesMaxBytes {
		return zero, cfg.ErrInvalid
	}
	copy := object.DeepCopy()
	copy.Data = map[string][]byte{"state.json": payload}
	response, err := s.preparer.creator.api.Put().AbsPath(resources.path()).Param("fieldValidation", "Strict").Body(copy).MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	result, _, err := resources.decode(ctx, response)
	if err != nil || result.UID != string(object.UID) || result.ResourceVersion == object.ResourceVersion || !equalJSON(result.State, next) || s.deadline(ctx) != nil {
		return zero, cfg.ErrUnavailable
	}
	return result, nil
}

// The only permitted writes add the first claim or its independently observed
// receipt. Sibling claims and the original resource inventory stay exact.
func cleanupProjectionTransition(before, after contracts.InitialRuntimeResourceState) bool {
	old, next := before.CleanupProjection, after.CleanupProjection
	before.CleanupProjection, after.CleanupProjection = nil, nil
	if !equalJSON(before, after) || next == nil {
		return false
	}
	if old == nil {
		return next.Receipt == nil
	}
	if old.Receipt != nil || next.Receipt == nil {
		return false
	}
	want := *next
	want.Receipt = nil
	return equalJSON(*old, want)
}
