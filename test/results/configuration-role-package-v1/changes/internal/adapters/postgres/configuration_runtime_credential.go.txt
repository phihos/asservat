package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifyConfigurationRuntimeCredential uses the runtime login itself and read-only
// PostgreSQL catalog checks. It cannot provision, repair or acknowledge a role.
// The immutable projection is historical provenance, never current recovery or
// permission authority. The owning reconciler separately constructs those gates; this manifest cannot supply fresh source or recovery authority.
func VerifyConfigurationRuntimeCredential(ctx context.Context, pool *pgxpool.Pool, m contracts.ConfigurationRuntimeCredentialManifest, purpose string) error {
	if ctx == nil || ctx.Err() != nil || pool == nil || m.Format != contracts.ConfigurationRuntimeCredentialManifestFormat || m.Input.Format != contracts.ConfigurationRuntimeRolesFormat || m.Input.LayoutDigest != ConfigurationRuntimeRoleLayoutDigest() || !authorization.UUID(m.RootUID) || !authorization.UUID(m.SetupID) || !authorization.UUID(m.Input.InitialClaimID) || !authorization.UUID(m.Input.InstallationID) || !authorization.UUID(m.Input.ClusterID) || !authorization.UUID(m.Input.Namespace.UID) {
		return cfg.ErrInvalid
	}
	purposes := contracts.ConfigurationRuntimeRolePurposes()
	if len(m.Roles) != len(purposes) {
		return cfg.ErrInvalid
	}
	var selected *contracts.ConfigurationRuntimeCredentialProof
	claims, roles := map[string]bool{m.SetupID: true}, map[uint32]bool{}
	for n := range m.Roles {
		r := &m.Roles[n]
		name, known := ConfigurationRuntimeRoleName(m.Input.InstallationID, r.Purpose)
		c := r.Claim
		if r.Purpose != purposes[n] || !known || r.Receipt.RoleName != name || r.Receipt.RoleOID == 0 || r.Receipt.RoleOID == 10 || roles[r.Receipt.RoleOID] || r.Receipt.LayoutDigest != m.Input.LayoutDigest || !authorization.UUID(c.OperationID) || claims[c.OperationID] || c.DatabaseOID == 0 || c.PostmasterAt.Year() < 2020 || c.PostmasterAt.After(c.ClaimedAt) || c.ClaimedAt.After(time.Now()) || c.ClaimedAt.Year() < 2020 || !c.ClaimedAt.Equal(c.ClaimedAt.Truncate(time.Microsecond)) || !c.Until.After(c.ClaimedAt) || c.Until.Sub(c.ClaimedAt) > 5*time.Second {
			return cfg.ErrInvalid
		}
		if !configurationRoleCurrentShape(m.Input, c.Sources, c.ClaimedAt) || c.Until.After(c.Sources.FreshUntil) {
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
	if e := pool.QueryRow(call, `SELECT current_user=session_user AND oid=$1 FROM pg_roles WHERE rolname=session_user`, selected.Receipt.RoleOID).Scan(&exact); e != nil || !exact {
		return cfg.ErrDenied
	}
	// The verifier methods below inspect only catalogs and original provenance;
	// no installer root or administrator connection exists in this path.
	v := &ConfigurationRuntimeSQLRoles{input: m.Input}
	snapshot := contracts.ConfigurationRuntimeRoleSnapshot{UID: m.RootUID, State: contracts.ConfigurationRuntimeRoleState{Input: m.Input, OperationID: m.SetupID}}
	provenance, e := json.Marshal(v.provenance(snapshot, purpose, selected.Claim))
	if e != nil {
		return cfg.ErrInvalid
	}
	material := contracts.ConfigurationRuntimeRoleMaterial{Purpose: purpose, Claim: &selected.Claim, Receipt: &selected.Receipt}
	if _, e = v.verify(call, pool, material, provenance); e != nil || call.Err() != nil {
		return cfg.ErrDenied
	}
	return nil
}
