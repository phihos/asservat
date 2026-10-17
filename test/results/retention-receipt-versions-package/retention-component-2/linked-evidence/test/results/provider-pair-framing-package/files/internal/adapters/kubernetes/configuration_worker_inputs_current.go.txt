package kubernetes

import (
	"bytes"
	"context"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

// Runs only within the original bridge SQL callback. It does not invoke the
// old resource current() path or a post-launch producer to establish its own
// prerequisites. All nineteen receipts and immutable parent facts are checked
// under the concrete retained guard before accepting this observation.
func (s *ConfigurationWorkerInputs) readResources(ctx context.Context) (contracts.InitialRuntimeResourceSnapshot, *core.Secret, error) {
	var zero contracts.InitialRuntimeResourceSnapshot
	before, _, _, phase, err := s.bridge.readCurrent(ctx)
	if err != nil {
		return zero, nil, err
	}
	if phase != 2 || before.State.Probe == nil || before.State.Probe.Receipt == nil || before.State.Retained == nil || before.State.Retained.Receipt == nil {
		return zero, nil, cfg.ErrUnavailable
	}
	call, end := context.WithDeadline(ctx, before.ValidUntil)
	defer end()
	v, obj, err := s.resources.read(call)
	if err != nil {
		return zero, nil, err
	}
	a, b := v.State, s.original.State
	if v.UID != s.original.UID || a.SetupID != b.SetupID || a.BindingDigest != b.BindingDigest || !a.CreatedAt.Equal(b.CreatedAt) || !a.Until.Equal(b.Until) ||
		a.WorkerLayout != b.WorkerLayout || a.OwnerLayout != b.OwnerLayout || !equalJSON(a.WorkerProvider, b.WorkerProvider) || !equalJSON(a.OwnerProvider, b.OwnerProvider) || !equalJSON(a.Objects, b.Objects) {
		return zero, nil, cfg.ErrChanged
	}
	inventory, err := s.resources.inventory(v.State)
	if err != nil || !equalJSON(inventory.BridgeAdministration, s.bridge.administration) {
		return zero, nil, cfg.ErrChanged
	}
	after, _, _, phase, err := s.bridge.readCurrent(call)
	if err != nil {
		return zero, nil, err
	}
	v.ValidUntil = identity.Earlier(v.ValidUntil, identity.Earlier(before.ValidUntil, after.ValidUntil))
	if phase != 2 || before.UID != after.UID || !equalJSON(before.State, after.State) {
		return zero, nil, cfg.ErrChanged
	}
	if initialHandoverDeadline(call, s.resources.now, v.ValidUntil) != nil {
		return zero, nil, cfg.ErrUnavailable
	}
	return v, obj, nil
}

func (s *ConfigurationWorkerInputs) currentRoles(ctx context.Context, original contracts.ConfigurationRuntimeRoleSnapshot, launched bool) error {
	var current contracts.ConfigurationRuntimeRoleSnapshot
	var err error
	if launched {
		current, err = s.roles.ReadLaunchedConfigurationRuntimeRoles(ctx)
	} else {
		current, _, err = s.roles.read(ctx)
	}
	if err != nil {
		return err
	}
	if current.UID != original.UID || !equalJSON(current.State, original.State) || !configurationRoleSameSources(current.Sources, original.Sources) || !launched && current.State.Launch != nil {
		return cfg.ErrChanged
	}
	until := identity.Earlier(original.ValidUntil, current.ValidUntil)
	if initialHandoverDeadline(ctx, s.resources.now, until) != nil {
		return cfg.ErrUnavailable
	}
	// Read the actual immutable SQL projection, not only the retained UID.
	data, err := configurationProjectionData(current.State)
	if err != nil {
		return err
	}
	defer clearRuntimeProjection(data)
	manifest, err := configurationProjectionManifest(current)
	if err != nil {
		return err
	}
	data[contracts.ConfigurationRuntimeRoleManifestFile] = manifest
	ref, err := s.roles.projection(ctx, current, data)
	if err != nil {
		return err
	}
	if current.State.Projection == nil || ref.UID != current.State.Projection.SecretUID {
		return cfg.ErrChanged
	}
	return initialHandoverDeadline(ctx, s.resources.now, until)
}

// This checks actual selected material and protects the dedicated whole-object
// read. It is not evidence of S3 IAM/conditional-write backend capability and
// never performs object-store I/O or logs/hashes credential content.
func (s *ConfigurationWorkerInputs) currentAuditCredentials(ctx context.Context, in contracts.HubWorkerDeployment) error {
	if in.ProviderAuthentication == nil {
		return cfg.ErrInvalid
	}
	ref := in.ProviderAuthentication.AuditCredentials
	raw, err := s.roles.client.api.Get().AbsPath("/api/v1/namespaces/" + in.Namespace.Name + "/secrets/" + ref.Name).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return cfg.ErrUnavailable
	}
	var obj core.Secret
	if permissionJSON(raw, permissionPageBytes, 131072) != nil || strictGuardJSON(raw, &obj) != nil {
		return cfg.ErrChanged
	}
	defer clearRuntimeProjection(obj.Data)
	if !initialProviderSecretIdentity(obj, in.Namespace.Name, ref, contracts.ConfigurationProviderAuditCredentialFile) || len(obj.Data) != 1 {
		return cfg.ErrChanged
	}
	credential, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(obj.Data[contracts.ConfigurationProviderAuditCredentialFile]))
	if err != nil || !identity.Text(credential.AccessKeyID, 256) || !identity.Text(credential.SecretAccessKey, 4096) || credential.SessionToken != "" && !identity.Text(credential.SessionToken, 16384) {
		return cfg.ErrUnavailable
	}
	until, ok := ctx.Deadline()
	if !ok {
		return cfg.ErrInvalid
	}
	return initialHandoverDeadline(ctx, s.resources.now, until)
}
