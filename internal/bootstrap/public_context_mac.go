package bootstrap

import (
	"bytes"
	"context"

	"asservat.local/asservat/internal/adapters/mounts"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

// newPublicOperationMAC reads the <name>-audit-mac keys the secrets Job
// generated once; their versions derive from the key file's own setup ID.
func newPublicOperationMAC(ctx context.Context, in *providerInputs, installation string) (*auditapp.OperationMAC, error) {
	if ctx == nil || ctx.Err() != nil || in == nil || in.files == nil || !authorization.UUID(installation) {
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
	if e != nil || v.Format != contracts.PublicAuditKeysFormat || v.InstallationID != installation || !authorization.UUID(v.SetupID) || v.Material.InputVersion != v.SetupID+"-input/v1" || v.Material.AccountVersion != v.SetupID+"-account/v1" || ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	return auditapp.NewOperationMAC(v.Material.InputVersion, v.Material.InputKey, v.Material.AccountVersion, v.Material.AccountKey)
}
