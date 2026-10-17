package kubernetes

import (
	"bytes"
	"context"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

// This method is reached only by the independently current launched-role
// reader. It can inspect the exact original provider2 result; it cannot claim,
// publish or launch it, and performs no external provider I/O under SQL locks.
func (s *ConfigurationRuntimeRoleRoot) configurationLaunchedInputs(ctx context.Context, state contracts.ConfigurationRuntimeRoleSnapshot, deployment apps.Deployment) error {
	input, object, err := s.readConfigurationLaunchInput(ctx, state)
	if err != nil {
		return err
	}
	if input.ProviderAuthentication == nil && input.ProviderInputs == nil {
		return s.configurationLegacyLaunchInputs(ctx, state, deployment, input)
	}
	return s.configurationProviderLaunchedInputs(ctx, state, deployment, input, object)
}

func (s *ConfigurationRuntimeRoleRoot) configurationProviderLaunchedInputs(ctx context.Context, state contracts.ConfigurationRuntimeRoleSnapshot, deployment apps.Deployment, input contracts.HubWorkerDeployment, object core.ConfigMap) error {
	l, a, p := state.State.Launch, input.Activation, input.ProviderAuthentication
	if l == nil || a == nil || p == nil || input.ProviderInputs == nil || a.WorkerLayout != contracts.HubWorkerProviderInstalledLayout || !HubWorkerActivationBound(input) ||
		state.State.Projection == nil || state.UID != input.ProviderInputs.ConfigurationRoot.UID || input.ProviderInputs.ConfigurationRoot.Name != s.name() ||
		state.State.OperationID != input.ProviderInputs.ConfigurationSetupID || state.State.Projection.SecretUID != input.ProviderInputs.SQLProjection.UID ||
		p.AuditCredentials != l.Providers || p.ServiceAccount != s.input.ServiceAccount || a.Deployment != s.input.Deployment ||
		!equalJSON(capacityActivationAdministration(input), s.source.protection.plan) ||
		a.WorkloadGuard.PolicyUID != s.source.protection.pin.PolicyUID || a.WorkloadGuard.PolicyGeneration != s.source.protection.pin.PolicyGeneration ||
		a.WorkloadGuard.BindingUID != s.source.protection.pin.BindingUID || a.WorkloadGuard.BindingResourceVersion != s.source.protection.pin.BindingResourceVersion {
		return cfg.ErrChanged
	}
	// The source reader independently proves the complete current namespace
	// guard/admin/source scope. Only borrow the fixed public-journal decoder;
	// runtime SelfSubjectReview is inappropriate for this administrator reader.
	reader := &InstalledWorkerProjectionReader{client: s.client, input: input}
	journal, err := reader.journal(ctx)
	if err != nil {
		return err
	}
	claim := journal.WorkerInputs
	if claim == nil || claim.Receipt == nil || claim.Receipt.Configuration != l.Configuration || claim.Receipt.ResourceVersion != object.ResourceVersion ||
		!equalJSON(configurationWorkerInputProvenance(claim), input.ProviderInputs) || claim.AuditCredentials != l.Providers ||
		len(object.BinaryData) != 0 || len(object.OwnerReferences) != 0 || len(object.Finalizers) != 0 || len(object.Labels) != 0 ||
		!equalJSON(object.Annotations, configurationWorkerInputAnnotations(a.Resources.UID, journal.SetupID, claim)) {
		return cfg.ErrChanged
	}
	digest, err := configurationWorkerInputDigest(input)
	if err != nil || digest != claim.PublicDigest {
		return cfg.ErrChanged
	}
	if !configurationProviderLaunchMounts(deployment, input, l) {
		return cfg.ErrChanged
	}
	var material core.Secret
	if err := s.readLaunchObject(ctx, "/api/v1/namespaces/"+input.Namespace.Name+"/secrets/"+l.Providers.Name, &material); err != nil {
		return err
	}
	defer clearRuntimeProjection(material.Data)
	if !initialProviderSecretIdentity(material, input.Namespace.Name, p.AuditCredentials, contracts.ConfigurationProviderAuditCredentialFile) || len(material.Data) != 1 {
		return cfg.ErrChanged
	}
	credential, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(material.Data[contracts.ConfigurationProviderAuditCredentialFile]))
	if err != nil || !identity.Text(credential.AccessKeyID, 256) || !identity.Text(credential.SecretAccessKey, 4096) || credential.SessionToken != "" && !identity.Text(credential.SessionToken, 16384) {
		return cfg.ErrUnavailable
	}
	return s.configurationLaunchProjection(ctx, state)
}

func configurationProviderLaunchMounts(d apps.Deployment, input contracts.HubWorkerDeployment, l *contracts.ConfigurationRuntimeLaunch) bool {
	if l == nil || input.ProviderAuthentication == nil || !HubWorkerActivationBound(input) || len(d.Spec.Template.Spec.Containers) != 1 || len(d.Spec.Template.Spec.InitContainers) != 0 || len(d.Spec.Template.Spec.EphemeralContainers) != 0 {
		return false
	}
	c, p := d.Spec.Template.Spec.Containers[0], input.ProviderAuthentication
	w, err := BuildProviderHubWorkerWorkload(HubWorkerWorkloadPlan{
		Namespace: d.Namespace, Name: d.Name, ServiceAccount: d.Spec.Template.Spec.ServiceAccountName,
		Configuration: l.Configuration.Name, Credentials: l.Providers.Name, Image: c.Image,
		FleetSource: input.FleetSource.Name, OwnerSource: input.OwnerSource.Name,
		FleetGuard: input.FleetGuard.Name, OwnerGuard: input.OwnerGuard.Name, LeaderLease: input.LeaderLease.Name,
	}, input.InstallationID, input.ClusterID, contracts.ConfigurationProviderSelection{AuthMount: p.AuthMount, AuthMountAccessor: p.AuthMountAccessor, AuditCredentials: p.AuditCredentials})
	if err != nil {
		return false
	}
	expected := w.Deployment.Spec.Template.Spec
	// The existing full running/inert spec digests still bind every field. These
	// explicit projections additionally establish the selected fixed profile.
	return equalJSON(d.Spec.Template.Spec.Volumes, expected.Volumes) && equalJSON(c.VolumeMounts, expected.Containers[0].VolumeMounts) &&
		equalJSON(c.Command, expected.Containers[0].Command) && equalJSON(c.Env, expected.Containers[0].Env) && len(c.Args) == 0 && len(c.EnvFrom) == 0
}
