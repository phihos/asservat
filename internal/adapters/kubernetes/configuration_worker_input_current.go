package kubernetes

import (
	"context"
	"strings"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

// Runtime reads only this public input and original public resource journal.
// It never opens the private SQL role journal. The mounted manifest is checked
// separately by the concrete SQL loader before opening its scoped connections.
func (s *InstalledWorkerProjectionReader) currentProviderInput(ctx context.Context, state contracts.InitialRuntimeResourceState) error {
	p, profile := state.WorkerInputs, s.input.ProviderAuthentication
	if profile == nil || state.WorkerProvider == nil || p == nil || p.Receipt == nil ||
		profile.AuthMount != state.WorkerProvider.AuthMount || profile.AuthMountAccessor != state.WorkerProvider.AuthMountAccessor || profile.AuditCredentials != state.WorkerProvider.AuditCredentials ||
		!equalJSON(profile.WorkerConfigurationAudit, state.WorkerProvider.WorkerConfigurationAudit) ||
		!equalJSON(profile.ContextDeletionSigning, state.WorkerProvider.ContextDeletionSigning) ||
		!equalJSON(s.input.ProviderInputs, configurationWorkerInputProvenance(p)) || !configurationWorkerInputsStateValid(s.input.InstallationID, state, s.client.now()) {
		return cfg.ErrChanged
	}
	digest, err := configurationWorkerInputDigest(s.input)
	if err != nil || digest != p.PublicDigest {
		return cfg.ErrChanged
	}
	var obj core.ConfigMap
	if err := s.get(ctx, "/api/v1/namespaces/"+s.input.Namespace.Name+"/configmaps/"+p.Receipt.Configuration.Name, &obj); err != nil {
		return err
	}
	if obj.APIVersion != "v1" || obj.Kind != "ConfigMap" || !ownerMetadata(obj.ObjectMeta, s.input.Namespace.Name, p.Receipt.Configuration.Name, p.Receipt.Configuration.UID) ||
		obj.ResourceVersion != p.Receipt.ResourceVersion || obj.Immutable == nil || !*obj.Immutable || len(obj.Data) != 1 || len(obj.BinaryData) != 0 ||
		len(obj.OwnerReferences) != 0 || len(obj.Finalizers) != 0 || len(obj.Labels) != 0 ||
		!equalJSON(obj.Annotations, configurationWorkerInputAnnotations(s.input.Activation.Resources.UID, state.SetupID, p)) {
		return cfg.ErrChanged
	}
	actual, err := contracts.DecodeHubWorkerDeployment(strings.NewReader(obj.Data["deployment.json"]))
	if err != nil || !equalJSON(actual, s.input) {
		return cfg.ErrChanged
	}
	until, ok := ctx.Deadline()
	if !ok {
		return cfg.ErrInvalid
	}
	return initialHandoverDeadline(ctx, s.client.now, until)
}
