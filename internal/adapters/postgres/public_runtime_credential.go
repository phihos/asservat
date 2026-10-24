package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifyPublicRuntimeCredential uses the runtime login itself and read-only
// PostgreSQL catalog checks. It cannot provision, repair or acknowledge a role.
// The immutable projection is historical provenance, never current recovery or
// permission authority. The owning runtime separately constructs those gates.
func VerifyPublicRuntimeCredential(ctx context.Context, pool *pgxpool.Pool, m contracts.PublicRuntimeCredentialManifest, purpose string) error {
	return verifyRuntimeCredential(ctx, pool, m, purpose, contracts.PublicRuntimeHubRolePurposes())
}

// VerifyPublisherRuntimeCredential checks one login of the publisher
// compartment against its own exact projection manifest (ADR-181).
func VerifyPublisherRuntimeCredential(ctx context.Context, pool *pgxpool.Pool, m contracts.PublicRuntimeCredentialManifest, purpose string) error {
	return verifyRuntimeCredential(ctx, pool, m, purpose, contracts.PublicRuntimePublisherPurposes())
}

func verifyRuntimeCredential(ctx context.Context, pool *pgxpool.Pool, m contracts.PublicRuntimeCredentialManifest, purpose string, purposes []string) error {
	if ctx == nil || ctx.Err() != nil || pool == nil || m.Format != contracts.PublicRuntimeCredentialManifestFormat || m.Input.Format != contracts.PublicRuntimeRolesFormat || !authorization.UUID(m.Input.OwnerConfigurationUID) || !authorization.UUID(m.RootUID) || !authorization.UUID(m.SetupID) || !authorization.UUID(m.Input.InitialClaimID) || !authorization.UUID(m.Input.InstallationID) || !authorization.UUID(m.Input.ClusterID) || !authorization.UUID(m.Input.Namespace.UID) {
		return cfg.ErrInvalid
	}
	if m.Input.LayoutDigest != PublicRuntimeRoleLayoutDigest() {
		return errors.Join(cfg.ErrInvalid, contracts.ErrPublicRuntimeLayout)
	}
	if len(m.Roles) != len(purposes) {
		return cfg.ErrInvalid
	}
	var selected *contracts.PublicRuntimeCredentialProof
	claims, roles := map[string]bool{m.SetupID: true}, map[uint32]bool{}
	for n := range m.Roles {
		r := &m.Roles[n]
		name, known := PublicRuntimeRoleName(m.Input.InstallationID, r.Purpose)
		c := r.Claim
		if r.Purpose != purposes[n] || !known || r.Receipt.RoleName != name || r.Receipt.RoleOID == 0 || r.Receipt.RoleOID == 10 || roles[r.Receipt.RoleOID] || r.Receipt.LayoutDigest != m.Input.LayoutDigest || !authorization.UUID(c.OperationID) || claims[c.OperationID] || c.DatabaseOID == 0 || c.PostmasterAt.Year() < 2020 || c.PostmasterAt.After(c.ClaimedAt) || c.ClaimedAt.After(time.Now()) || c.ClaimedAt.Year() < 2020 || !c.ClaimedAt.Equal(c.ClaimedAt.Truncate(time.Microsecond)) || !c.Until.After(c.ClaimedAt) || c.Until.Sub(c.ClaimedAt) > 5*time.Second {
			return cfg.ErrInvalid
		}
		claims[c.OperationID], roles[r.Receipt.RoleOID] = true, true
		if r.Purpose == purpose {
			selected = r
		}
	}
	limit, known := contracts.PublicRuntimeRolePoolLimit(purpose)
	poolLimit := pool.Config().MaxConns
	validPool := poolLimit == int32(limit)
	if purpose == "hub-runtime" {
		validPool = poolLimit == contracts.PublicRuntimeHubOrdinaryConnections || poolLimit == 1
	}
	if selected == nil || !known || pool.Config().ConnConfig.User != selected.Receipt.RoleName || !validPool {
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
	v := &PublicRuntimeSQLRoles{input: m.Input}
	snapshot := contracts.PublicRuntimeRoleSnapshot{UID: m.RootUID, State: contracts.PublicRuntimeRoleState{Input: m.Input, OperationID: m.SetupID}}
	provenance, e := json.Marshal(v.provenance(snapshot, purpose, selected.Claim))
	if e != nil {
		return cfg.ErrInvalid
	}
	material := contracts.PublicRuntimeRoleMaterial{Purpose: purpose, Claim: &selected.Claim, Receipt: &selected.Receipt}
	if _, e = v.verify(call, pool, material, provenance); e != nil || call.Err() != nil {
		return cfg.ErrDenied
	}
	return nil
}

// VerifyPermissionRuntimeCredential checks one hub-worker permission login
// against its projection manifest (ADR-189), with the same catalog proof.
func VerifyPermissionRuntimeCredential(ctx context.Context, pool *pgxpool.Pool, m contracts.PermissionCredentialManifest, purpose string) error {
	if m.Format != contracts.PermissionCredentialManifestFormat {
		return cfg.ErrInvalid
	}
	// The ordered list is exact; a retention section adds its four logins, a
	// worker configuration section its two (ADR-204) and a context deletion
	// section its three (ADR-205), a browser section its one (ADR-210). A
	// manifest naming any of a section's logins must carry exactly that
	// section's ordered list.
	var retention, worker, deletion, browser bool
	for _, r := range m.Roles {
		retention = retention || slices.Contains(contracts.PublicRuntimeRetentionPurposes(), r.Purpose)
		worker = worker || slices.Contains(contracts.PublicRuntimeWorkerConfigurationPurposes(), r.Purpose)
		deletion = deletion || slices.Contains(contracts.PublicRuntimeContextDeletionPurposes(), r.Purpose)
		browser = browser || r.Purpose == "browser-settings"
	}
	purposes := contracts.PermissionProjectionPurposes(retention, worker, deletion, browser)
	return verifyRuntimeCredential(ctx, pool, contracts.PublicRuntimeCredentialManifest{Format: contracts.PublicRuntimeCredentialManifestFormat, Input: m.Input, RootUID: m.RootUID, SetupID: m.SetupID, Roles: m.Roles}, purpose, purposes)
}
