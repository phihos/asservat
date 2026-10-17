package kubernetes

import (
	"bytes"
	"context"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

// Only the original immutable SQL3 object and one dedicated mutable storage
// object are read. Both are already fully mounted into this exact workload.
func (s *InstalledWorkerProjectionReader) configurationProviderProjection(ctx context.Context, m contracts.ConfigurationRuntimeCredentialManifest, mounted map[string][]byte) error {
	in, p := s.input, s.input.ProviderInputs
	if p == nil || in.ProviderAuthentication == nil || m.Format != contracts.ConfigurationRuntimeCredentialManifestFormat || m.RootUID != p.ConfigurationRoot.UID || m.SetupID != p.ConfigurationSetupID ||
		m.Input.Format != contracts.ConfigurationRuntimeRolesFormat || m.Input.InstallationID != in.InstallationID || m.Input.ClusterID != in.ClusterID || m.Input.Namespace != in.Namespace || m.Input.Deployment != in.Activation.Deployment || m.Input.ServiceAccount != in.Activation.ServiceAccount || m.Input.FleetSource != in.FleetSource || m.Input.OwnerSource != in.OwnerSource ||
		p.SQLProjection.Name != configurationWorkerSQLProjectionName(in.InstallationID) || p.ConfigurationRoot.Name != configurationWorkerRoleRootName(in.InstallationID) || !authorization.UUID(m.Input.InitialClaimID) {
		return cfg.ErrChanged
	}
	keys := []string{contracts.ConfigurationRuntimeRoleManifestFile, "sql-fleet.json", "sql-configuration.json", "sql-audit.json"}
	if len(mounted) != len(keys)+1 || len(m.Roles) != 3 {
		return cfg.ErrChanged
	}
	var obj core.Secret
	base := "/api/v1/namespaces/" + in.Namespace.Name + "/secrets/"
	if err := s.get(ctx, base+p.SQLProjection.Name, &obj); err != nil {
		return err
	}
	defer clearRuntimeProjection(obj.Data)
	if obj.APIVersion != "v1" || obj.Kind != "Secret" || !ownerMetadata(obj.ObjectMeta, in.Namespace.Name, p.SQLProjection.Name, p.SQLProjection.UID) || obj.Immutable == nil || !*obj.Immutable || obj.Type != core.SecretTypeOpaque || len(obj.OwnerReferences) != 0 || len(obj.Finalizers) != 0 || len(obj.Labels) != 0 || len(obj.StringData) != 0 || len(obj.Data) != len(keys) || len(obj.Annotations) != 3 || obj.Annotations["asservat.io/role-root-uid"] != m.RootUID || obj.Annotations["asservat.io/role-setup-id"] != m.SetupID || !authorization.UUID(obj.Annotations["asservat.io/projection-id"]) {
		return cfg.ErrChanged
	}
	for _, key := range keys {
		if len(mounted[key]) == 0 || len(mounted[key]) > contracts.ConfigurationRuntimeRoleMaxBytes || !bytes.Equal(obj.Data[key], mounted[key]) {
			return cfg.ErrChanged
		}
	}
	actual, err := contracts.DecodeConfigurationRuntimeCredentialManifest(bytes.NewReader(obj.Data[contracts.ConfigurationRuntimeRoleManifestFile]))
	if err != nil || !equalJSON(actual, m) {
		return cfg.ErrChanged
	}
	purposes := contracts.ConfigurationRuntimeRolePurposes()
	for i, key := range keys[1:] {
		credential, e := contracts.DecodeOwnerSQLCredential(bytes.NewReader(obj.Data[key]))
		if e != nil || m.Roles[i].Purpose != purposes[i] || m.Roles[i].Receipt.RoleName != credential.Username || credential.Password == "" {
			return cfg.ErrChanged
		}
	}
	ref := in.ProviderAuthentication.AuditCredentials
	var storage core.Secret
	if err = s.get(ctx, base+ref.Name, &storage); err != nil {
		return err
	}
	defer clearRuntimeProjection(storage.Data)
	key := contracts.ConfigurationProviderAuditCredentialFile
	if storage.APIVersion != "v1" || storage.Kind != "Secret" || !ownerMetadata(storage.ObjectMeta, in.Namespace.Name, ref.Name, ref.UID) || storage.Immutable != nil && *storage.Immutable || storage.Type != core.SecretTypeOpaque || len(storage.OwnerReferences) != 0 || len(storage.Finalizers) != 0 || len(storage.Labels) != 0 || len(storage.Annotations) != 0 || len(storage.StringData) != 0 || len(storage.Data) != 1 || len(mounted[key]) == 0 || len(mounted[key]) > 32<<10 || !bytes.Equal(storage.Data[key], mounted[key]) {
		return cfg.ErrChanged
	}
	credential, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(storage.Data[key]))
	if err != nil || !configurationWorkerStorageCredentialValid(credential) {
		return cfg.ErrChanged
	}
	return nil
}

// Fixed-key comparison is local material verification, never an S3 capability
// claim. Backend conditional-create/version/deletion qualification is separate.
func configurationWorkerStorageCredentialValid(v contracts.OwnerStorageCredential) bool {
	return identity.Text(v.AccessKeyID, 256) && identity.Text(v.SecretAccessKey, 4096) && (v.SessionToken == "" || identity.Text(v.SessionToken, 16384))
}
