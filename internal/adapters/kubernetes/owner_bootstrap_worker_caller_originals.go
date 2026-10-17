package kubernetes

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
)

// This reads only the fixed configuration predecessor already named by the
// original positive WorkerInputs receipt. A same-shaped replacement is never
// adopted, and this path opens no SQL connection or runtime provider token.
func (s *OwnerIdentityRoleRoot) readOwnerWorkerCallerRoles(ctx context.Context, current ownerIdentityOperationNative) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	var zero contracts.ConfigurationRuntimeRoleSnapshot
	w := current.retained.resources.State.WorkerInputs
	in := s.bridge.source.input
	if w == nil || w.Receipt == nil || w.ConfigurationRoot.Name != "asservat-configuration-roles-"+strings.ReplaceAll(in.InstallationID, "-", "") {
		return zero, cfg.ErrChanged
	}
	raw, err := s.bridge.source.client.api.Get().AbsPath("/api/v1/namespaces/" + in.Namespace.Name + "/secrets/" + w.ConfigurationRoot.Name).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	var obj core.Secret
	if permissionJSON(raw, permissionPageBytes, 131072) != nil || strictGuardJSON(raw, &obj) != nil {
		return zero, cfg.ErrChanged
	}
	defer clearRuntimeProjection(obj.Data)
	if obj.APIVersion != "v1" || obj.Kind != "Secret" || !ownerMetadata(obj.ObjectMeta, in.Namespace.Name, w.ConfigurationRoot.Name, w.ConfigurationRoot.UID) ||
		len(obj.OwnerReferences) != 0 || len(obj.Finalizers) != 0 || len(obj.Labels) != 0 || len(obj.Annotations) != 0 ||
		obj.Type != core.SecretTypeOpaque || obj.Immutable != nil && *obj.Immutable || len(obj.StringData) != 0 || len(obj.Data) != 1 {
		return zero, cfg.ErrChanged
	}
	state, err := contracts.DecodeConfigurationRuntimeRoleState(bytes.NewReader(obj.Data["state.json"]))
	if err != nil || !configurationRoleStateValid(in, state, s.resources.now()) || state.OperationID != w.ConfigurationSetupID ||
		state.Launch == nil || state.Launch.Receipt == nil || state.Projection == nil || state.Projection.SecretUID != w.SQLProjection.UID ||
		state.Launch.Configuration != w.Receipt.Configuration || state.Launch.Providers != w.AuditCredentials {
		return zero, cfg.ErrChanged
	}
	if initialHandoverDeadline(ctx, s.resources.now, current.until) != nil {
		return zero, cfg.ErrUnavailable
	}
	return contracts.ConfigurationRuntimeRoleSnapshot{State: state, UID: string(obj.UID), ResourceVersion: obj.ResourceVersion}, nil
}

func (s *OwnerIdentityRoleRoot) ownerWorkerCallerOriginals(ctx context.Context, current ownerIdentityOperationNative, roles contracts.ConfigurationRuntimeRoleSnapshot, selection contracts.OwnerBootstrapSelection) (OwnerBootstrapWorkerCaller, error) {
	var zero OwnerBootstrapWorkerCaller
	state := current.retained.resources.State
	p := state.OwnerBootstrap
	if p == nil || p.Child == nil || p.Child.Receipt == nil || !ownerBootstrapBodyBound(s, p, selection) || current.input != s.input ||
		roles.State.Input != s.bridge.source.input || roles.State.Launch == nil || roles.State.Launch.Receipt == nil {
		return zero, cfg.ErrChanged
	}
	inventory, err := s.resources.inventory(state)
	if err != nil {
		return zero, err
	}
	worker, err := BuildPublicRuntimeWorkerBinding(current.retained.resources, inventory, roles)
	if err != nil {
		return zero, err
	}
	guard := s.bridge.source.protection
	if state.WorkerLayout != contracts.HubWorkerProviderInstalledLayout || state.OwnerLayout != contracts.OwnerProviderInstalledLayout ||
		inventory.WorkloadGuard.PolicyUID != guard.pin.PolicyUID || inventory.WorkloadGuard.PolicyGeneration != guard.pin.PolicyGeneration ||
		inventory.WorkloadGuard.BindingUID != guard.pin.BindingUID || inventory.WorkloadGuard.BindingResourceVersion != guard.pin.BindingResourceVersion ||
		!equalJSON(inventory.BridgeAdministration.Owner, guard.plan) {
		return zero, cfg.ErrChanged
	}
	if err = s.ownerIdentityOperationOriginalObject(ctx, current.source.account, state, 1); err != nil {
		return zero, err
	}
	d := current.source.deployment
	l := roles.State.Launch
	if _, ok := configurationWorkerOriginalLaunchSources(current.source.proof.observation, d, roles); !ok ||
		d.Generation != state.Objects[11].Receipt.Generation+1 || len(d.Spec.Template.Spec.Containers) != 1 {
		return zero, cfg.ErrChanged
	}
	// Verify the complete original generated Deployment, allowing only the exact
	// acknowledged replicas transition and its one launch marker. API status/RV
	// defaults use the existing qualified resource decoder; no template, label,
	// annotation, image or security field is discarded for comparison.
	original := d.DeepCopy()
	*original.Spec.Replicas = 0
	original.Generation = state.Objects[11].Receipt.Generation
	delete(original.Annotations, configurationLaunchAnnotation)
	raw, err := json.Marshal(original)
	if err != nil {
		return zero, cfg.ErrChanged
	}
	if _, err = s.resources.verified(ctx, raw, state, 11); err != nil {
		return zero, err
	}
	template, err := ConnectorAPITemplateDigest(d.Spec.Template)
	if err != nil {
		return zero, err
	}
	image := strings.Split(d.Spec.Template.Spec.Containers[0].Image, "@sha256:")
	if len(image) != 2 || !ownerIdentityDigestValid(image[1]) {
		return zero, cfg.ErrChanged
	}
	imageBytes, _ := hex.DecodeString(image[1])
	pin := fleet.ClusterObservationCallerPin{RootID: selection.PermissionRootID, InstallationID: s.input.InstallationID, ClusterID: s.input.ClusterID,
		Namespace: cfg.NamespaceRef{Name: inventory.Namespace.Name, UID: inventory.Namespace.UID},
		Account:   worker.Account.Reference.Name, AccountUID: worker.Account.Reference.UID,
		Deployment: worker.Deployment.Reference.Name, DeploymentUID: worker.Deployment.Reference.UID,
		TemplateDigest: template, ProtectionDigest: guard.digest}
	copy(pin.ImageDigest[:], imageBytes)
	if !pin.Valid() || pin.DeploymentUID == s.input.Deployment.UID || pin.AccountUID == s.input.ServiceAccount.UID {
		return zero, cfg.ErrChanged
	}
	if initialHandoverDeadline(ctx, s.resources.now, current.until) != nil {
		return zero, cfg.ErrUnavailable
	}
	return OwnerBootstrapWorkerCaller{Pin: pin, Resources: worker.Resources, ResourceSetupID: worker.ResourceSetupID, ResourceBinding: worker.ResourceBinding,
		Selection: p.Child.Receipt.Object, SelectionOperationID: p.OperationID, SelectionPublicDigest: p.PublicDigest,
		ConfigurationRoot: worker.ConfigurationRoot, ConfigurationSetupID: worker.ConfigurationSetupID,
		WorkerInputID: worker.Provider.InputOperationID, LaunchOperationID: l.OperationID}, nil
}

func (s *OwnerIdentityRoleRoot) ownerObservationParticipant(current ownerIdentityOperationNative, caller OwnerBootstrapWorkerCaller) (fleet.OwnerObservationPin, error) {
	var zero fleet.OwnerObservationPin
	state := current.retained.resources.State
	selected := state.OwnerBootstrap
	if selected == nil || selected.Child == nil || selected.Child.Receipt == nil || state.ObservationFormat != contracts.OwnerObservationOperationFormat ||
		selected.ObservationFormat != state.ObservationFormat || s.resources.observationFormat != state.ObservationFormat || current.input != s.input ||
		caller.Pin.RootID != selected.PermissionRootID || caller.Selection != selected.Child.Receipt.Object || caller.ResourceBinding != state.BindingDigest {
		return zero, cfg.ErrChanged
	}
	deployment := current.source.ownerDeployment
	if len(deployment.Spec.Template.Spec.Containers) != 1 {
		return zero, cfg.ErrChanged
	}
	template, err := ConnectorAPITemplateDigest(deployment.Spec.Template)
	if err != nil {
		return zero, cfg.ErrChanged
	}
	image := strings.Split(deployment.Spec.Template.Spec.Containers[0].Image, "@sha256:")
	if len(image) != 2 || !ownerIdentityDigestValid(image[1]) {
		return zero, cfg.ErrChanged
	}
	imageBytes, err := hex.DecodeString(image[1])
	if err != nil {
		return zero, cfg.ErrChanged
	}
	pin := fleet.OwnerObservationPin{RootID: selected.PermissionRootID, SourceUID: s.input.OwnerConfigurationUID,
		Pool: current.source.owner.Pool, TemplateDigest: template, ProtectionDigest: s.bridge.source.protection.digest}
	copy(pin.ImageDigest[:], imageBytes)
	if !pin.Valid() || pin.Pool.DeploymentUID != s.input.Deployment.UID || pin.Pool.AccountUID != s.input.ServiceAccount.UID ||
		pin.Pool.DeploymentUID == caller.Pin.DeploymentUID || pin.Pool.AccountUID == caller.Pin.AccountUID {
		return zero, cfg.ErrChanged
	}
	return pin, nil
}
