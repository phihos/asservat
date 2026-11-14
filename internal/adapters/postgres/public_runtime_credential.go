package postgres

import (
	"context"
	"slices"

	"asservat.local/asservat/internal/contracts"
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

func verifyRuntimeCredential(ctx context.Context, pool *pgxpool.Pool, m contracts.PublicRuntimeCredentialManifest, purpose string, purposes []string) error {
	if !slices.Contains(purposes, purpose) {
		return cfg.ErrInvalid
	}
	name, known := PublicRuntimeRoleName(m.Input.InstallationID, purpose)
	if !known {
		return cfg.ErrInvalid
	}
	return VerifySessionRole(ctx, pool, name)
}
