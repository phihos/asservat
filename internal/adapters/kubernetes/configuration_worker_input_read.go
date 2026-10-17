package kubernetes

import (
	"bytes"
	"context"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

func configurationWorkerInputAnnotations(resourceUID, setupID string, p *contracts.ConfigurationWorkerInputClaim) map[string]string {
	return capacityProjectionAnnotations(resourceUID, setupID, &contracts.CapacityRuntimeProjectionClaim{OperationID: p.OperationID, PublicDigest: p.PublicDigest})
}

// The role producer checks the actual immutable public ConfigMap against its
// original independently pinned worker provenance. Neither the journal alone
// nor a known v2 marker can promote a changed selection or missing predecessor.
func (s *PublicRuntimeRoleRoot) currentWorkerProviderInput(ctx context.Context, resources contracts.InitialRuntimeResourceState, roles contracts.ConfigurationRuntimeRoleState) error {
	w := s.input.Worker
	p := resources.WorkerInputs
	if p == nil || p.Receipt == nil || roles.Projection == nil || roles.Projection.SecretUID != p.SQLProjection.UID ||
		roles.OperationID != p.ConfigurationSetupID || roles.Launch == nil || roles.Launch.Receipt == nil ||
		roles.Launch.Configuration != p.Receipt.Configuration || roles.Launch.Providers != p.AuditCredentials {
		return cfg.ErrChanged
	}
	var obj core.ConfigMap
	if err := s.workerRead(ctx, "/api/v1/namespaces/"+s.input.Namespace.Name+"/configmaps/"+p.Receipt.Configuration.Name, &obj); err != nil {
		return err
	}
	if obj.APIVersion != "v1" || obj.Kind != "ConfigMap" || !ownerMetadata(obj.ObjectMeta, s.input.Namespace.Name, p.Receipt.Configuration.Name, p.Receipt.Configuration.UID) ||
		obj.ResourceVersion != p.Receipt.ResourceVersion || obj.Immutable == nil || !*obj.Immutable || len(obj.Data) != 1 || len(obj.BinaryData) != 0 ||
		len(obj.OwnerReferences) != 0 || len(obj.Finalizers) != 0 || len(obj.Labels) != 0 ||
		!equalJSON(obj.Annotations, configurationWorkerInputAnnotations(w.Resources.UID, w.ResourceSetupID, p)) {
		return cfg.ErrChanged
	}
	in, err := contracts.DecodeHubWorkerDeployment(bytes.NewBufferString(obj.Data["deployment.json"]))
	if err != nil || in.ProviderAuthentication == nil || !HubWorkerActivationBound(in) ||
		in.InstallationID != s.input.InstallationID || in.ClusterID != s.input.ClusterID || in.Namespace != s.input.Namespace ||
		in.FleetSource != roles.Input.FleetSource || in.OwnerSource != roles.Input.OwnerSource ||
		!equalJSON(in.ProviderInputs, configurationWorkerInputProvenance(p)) ||
		providerconfig.ValidateConfigurationProviderAuthentication(in, *in.ProviderAuthentication, s.client.now()) != nil {
		return cfg.ErrChanged
	}
	a, profile := in.Activation, in.ProviderAuthentication
	if a.Resources != w.Resources || a.SetupID != w.ResourceSetupID || a.BindingDigest != w.ResourceBinding || a.WorkerLayout != w.WorkerLayout ||
		a.Deployment != w.Deployment.Reference || a.ServiceAccount != w.Account.Reference || !a.CreatedAt.Equal(resources.CreatedAt) || !a.Until.Equal(resources.Until) ||
		profile.AuthMount != w.Provider.Selection.AuthMount || profile.AuthMountAccessor != w.Provider.Selection.AuthMountAccessor || profile.AuditCredentials != w.Provider.Selection.AuditCredentials ||
		profile.ServiceAccount != w.Account.Reference {
		return cfg.ErrChanged
	}
	digest, err := configurationWorkerInputDigest(in)
	if err != nil || digest != p.PublicDigest {
		return cfg.ErrChanged
	}
	until, ok := ctx.Deadline()
	if !ok {
		return cfg.ErrInvalid
	}
	return initialHandoverDeadline(ctx, s.client.now, until)
}
