package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

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
	if ctx == nil || ctx.Err() != nil || pool == nil || m.Format != contracts.OwnerIdentityCredentialManifestFormat || !validOwnerIdentityRoleInput(m.Input) || !authorization.UUID(m.RootUID) || !authorization.UUID(m.SetupID) {
		return cfg.ErrInvalid
	}
	purposes := contracts.OwnerIdentityRolePurposes()
	if len(m.Roles) != len(purposes) {
		return cfg.ErrInvalid
	}
	claims, roles := map[string]bool{m.SetupID: true}, map[uint32]bool{}
	var selected *contracts.PublicRuntimeCredentialProof
	now := time.Now()
	for i := range m.Roles {
		r := &m.Roles[i]
		name, known := OwnerIdentityRoleName(m.Input.InstallationID, r.Purpose)
		c := r.Claim
		if r.Purpose != purposes[i] || !known || r.Receipt.RoleName != name || r.Receipt.RoleOID == 0 || r.Receipt.RoleOID == 10 || roles[r.Receipt.RoleOID] || r.Receipt.LayoutDigest != m.Input.LayoutDigest || !authorization.UUID(c.OperationID) || claims[c.OperationID] || c.DatabaseOID == 0 || c.PostmasterAt.Year() < 2020 || c.PostmasterAt.After(c.ClaimedAt) || c.ClaimedAt.After(now) || c.ClaimedAt.Year() < 2020 || !c.ClaimedAt.Equal(c.ClaimedAt.Truncate(time.Microsecond)) || !c.Until.Equal(c.Until.Truncate(time.Microsecond)) || !c.Until.After(c.ClaimedAt) || c.Until.Sub(c.ClaimedAt) > 5*time.Second {
			return cfg.ErrInvalid
		}
		claims[c.OperationID], roles[r.Receipt.RoleOID] = true, true
		if r.Purpose == purpose {
			selected = r
		}
	}
	if selected == nil || pool.Config().ConnConfig.User != selected.Receipt.RoleName || pool.Config().MaxConns != 1 {
		return cfg.ErrDenied
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var exact bool
	if err := pool.QueryRow(call, `SELECT current_user=session_user AND oid=$1 FROM pg_roles WHERE rolname=session_user`, selected.Receipt.RoleOID).Scan(&exact); err != nil || !exact {
		return cfg.ErrDenied
	}
	provenance, err := json.Marshal(ownerIdentityProvenance(m.Input, m.RootUID, m.SetupID, purpose, selected.Claim))
	if err != nil {
		return cfg.ErrInvalid
	}
	grants, ok := ownerIdentityRoleGrants(purpose)
	if !ok {
		return cfg.ErrInvalid
	}
	if _, err = verifyFixedRuntimeRole(call, pool, selected.Receipt.RoleName, contracts.OwnerIdentityRoleConnections, m.Input.LayoutDigest, &selected.Receipt, provenance, grants); err != nil || call.Err() != nil {
		return cfg.ErrDenied
	}
	return nil
}
