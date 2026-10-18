package bootstrap

import (
	"bytes"
	"context"
	"os"

	"asservat.local/asservat/internal/adapters/mounts"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

func newPublicOperationMAC(ctx context.Context, in *providerInputs, installation string, original contracts.PublicRuntimeCredentialManifest) (*auditapp.OperationMAC, error) {
	if ctx == nil || ctx.Err() != nil || in == nil || in.files == nil || original.Input.InstallationID != installation || !authorization.UUID(original.RootUID) || !authorization.UUID(original.SetupID) {
		return nil, mounts.ErrUnavailable
	}
	b, e := in.read(ctx, contracts.PublicAuditKeysFile, contracts.PublicAuditKeysMaxBytes)
	if e != nil {
		return nil, mounts.ErrUnavailable
	}
	defer clear(b)
	v, e := contracts.DecodePublicAuditKeys(bytes.NewReader(b))
	defer clear(v.Material.InputKey)
	defer clear(v.Material.AccountKey)
	if e != nil || v.Format != contracts.PublicAuditKeysFormat || v.InstallationID != original.Input.InstallationID || v.RootUID != original.RootUID || v.SetupID != original.SetupID || v.Material.InputVersion != v.SetupID+"-input/v1" || v.Material.AccountVersion != v.SetupID+"-account/v1" || ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	return auditapp.NewOperationMAC(v.Material.InputVersion, v.Material.InputKey, v.Material.AccountVersion, v.Material.AccountKey)
}

// ReadProjectedCaptureAccounts consumes the capacity compartment's fixed
// immutable projection only. The caller must have independently verified the
// protected deployment/root/setup identities and keeps that source current.
// No account key can initialize, accept or renew capacity on its own.
func ReadProjectedCaptureAccounts(ctx context.Context, files *os.Root, installation, rootUID, setupID, version string) (*auditapp.CaptureAccounts, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || !authorization.UUID(installation) || !authorization.UUID(rootUID) || !authorization.UUID(setupID) || version != setupID+"-account/v1" {
		return nil, mounts.ErrUnavailable
	}
	b, e := mounts.Read(ctx, files, contracts.CaptureAccountKeyFile, contracts.PublicAuditKeysMaxBytes)
	if e != nil {
		return nil, mounts.ErrUnavailable
	}
	defer clear(b)
	v, e := contracts.DecodeCaptureAccountKey(bytes.NewReader(b))
	defer clear(v.Key)
	if e != nil || v.Format != contracts.CaptureAccountKeyFormat || v.InstallationID != installation || v.RootUID != rootUID || v.SetupID != setupID || v.Version != version || ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	return auditapp.NewCaptureAccounts(installation, v.Version, v.Key)
}
