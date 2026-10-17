package kubernetes

import (
	"bytes"
	"context"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

func (s *ConfigurationWorkerInputs) readWorkerOperationOwnerAccount(ctx context.Context, native configurationWorkerNative) (core.ServiceAccount, error) {
	var zero core.ServiceAccount
	ref := s.bridge.administration.OwnerProbe
	reader := &OwnerEndpoints{client: s.roles.client, pool: native.owner.Pool}
	account, err := ownerResource[core.ServiceAccount](reader, ctx, "/api/v1/namespaces/"+s.roles.input.Namespace.Name+"/serviceaccounts/"+ref.ServiceAccount, "v1", "ServiceAccount")
	if err != nil {
		return zero, err
	}
	if !native.proof.native.matches(s.roles.source, s.bridge.administration, account) {
		return zero, cfg.ErrChanged
	}
	return account, nil
}

// Exactly one actual immutable projection GET, using only the original private
// role journal's complete expected bytes. It does not obtain source authority.
func (s *ConfigurationWorkerInputs) readWorkerOperationProjection(ctx context.Context, current contracts.ConfigurationRuntimeRoleSnapshot) error {
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
	return initialHandoverDeadline(ctx, s.resources.now, current.ValidUntil)
}

// Exactly one actual selected Secret GET. The operation compares its complete
// value/RV to this owned response at later boundaries, then clears it at close.
// It never logs or persists private credential bytes or their digest.
func (s *ConfigurationWorkerInputs) readWorkerOperationAudit(ctx context.Context, in contracts.HubWorkerDeployment) (core.Secret, error) {
	var zero core.Secret
	if in.ProviderAuthentication == nil {
		return zero, cfg.ErrInvalid
	}
	ref := in.ProviderAuthentication.AuditCredentials
	raw, err := s.roles.client.api.Get().AbsPath("/api/v1/namespaces/" + in.Namespace.Name + "/secrets/" + ref.Name).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	var obj core.Secret
	if permissionJSON(raw, permissionPageBytes, 131072) != nil || strictGuardJSON(raw, &obj) != nil {
		return zero, cfg.ErrChanged
	}
	good := false
	defer func() {
		if !good {
			clearRuntimeProjection(obj.Data)
		}
	}()
	if !initialProviderSecretIdentity(obj, in.Namespace.Name, ref, contracts.ConfigurationProviderAuditCredentialFile) || len(obj.Data) != 1 {
		return zero, cfg.ErrChanged
	}
	credential, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(obj.Data[contracts.ConfigurationProviderAuditCredentialFile]))
	if err != nil || !identity.Text(credential.AccessKeyID, 256) || !identity.Text(credential.SecretAccessKey, 4096) || credential.SessionToken != "" && !identity.Text(credential.SessionToken, 16384) {
		return zero, cfg.ErrUnavailable
	}
	until, ok := ctx.Deadline()
	if !ok || initialHandoverDeadline(ctx, s.resources.now, until) != nil {
		return zero, cfg.ErrUnavailable
	}
	good = true
	return obj, nil
}
