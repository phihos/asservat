package postgres

import (
	"context"
	"encoding/hex"
	"strings"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

func validOwnerIdentityRoleInput(in contracts.OwnerIdentityRoles) bool {
	if in.Format != contracts.OwnerIdentityRolesFormat || in.LayoutDigest != OwnerIdentityRoleLayoutDigest() || in.OwnerLayout != contracts.OwnerInstalledLayout && in.OwnerLayout != contracts.OwnerProviderInstalledLayout {
		return false
	}
	for _, id := range []string{in.InstallationID, in.InitialClaimID, in.ClusterID, in.OwnerConfigurationUID, in.ResourceSetupID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	for _, ref := range []contracts.WorkerObjectReference{in.Namespace, in.Resources, in.Deployment, in.ServiceAccount} {
		if !authorization.UUID(ref.UID) || len(ref.Name) == 0 || len(ref.Name) > 253 || strings.ContainsAny(ref.Name, "\x00\r\n/\\") {
			return false
		}
	}
	d, err := hex.DecodeString(in.ResourceBinding)
	return err == nil && len(d) == 32 && hex.EncodeToString(d) == in.ResourceBinding && in.ResourceBinding != strings.Repeat("0", 64)
}

// The source scope is immutable provenance. Current accepted configuration,
// recovery, private workload protection and process activation remain separate.
type ownerIdentityRoleProvenance struct {
	Format, RootUID, SetupID, Purpose string
	Input                             contracts.OwnerIdentityRoles
	Claim                             contracts.PublicRuntimeRoleClaim
}

func ownerIdentityProvenance(in contracts.OwnerIdentityRoles, root, setup, purpose string, claim contracts.PublicRuntimeRoleClaim) ownerIdentityRoleProvenance {
	return ownerIdentityRoleProvenance{"asservat-owner-identity-role/v1", root, setup, purpose, in, claim}
}

// VerifyOwnerIdentityCredential uses only the actual scoped runtime login. It
// compares exact original role OID/provenance/ACL and bounded connection state;
// it cannot create or repair a role or approve collection/recovery. The caller
// must first match the manifest input to the original acknowledged installation
// projections and current exact Pod/workload. Manifest presence is not proof.
func VerifyOwnerIdentityCredential(ctx context.Context, pool *pgxpool.Pool, m contracts.OwnerIdentityCredentialManifest, purpose string) error {
	name, known := OwnerIdentityRoleName(m.Input.InstallationID, purpose)
	if !known {
		return cfg.ErrInvalid
	}
	return VerifySessionRole(ctx, pool, name)
}
