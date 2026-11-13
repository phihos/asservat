package postgres

import (
	"context"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifyConfigurationRuntimeCredential uses the runtime login itself and read-only
// PostgreSQL catalog checks. It cannot provision, repair or acknowledge a role.
// The immutable projection is historical provenance, never current recovery or
// permission authority. The owning reconciler separately constructs those gates; this manifest cannot supply fresh source or recovery authority.
func VerifyConfigurationRuntimeCredential(ctx context.Context, pool *pgxpool.Pool, m contracts.ConfigurationRuntimeCredentialManifest, purpose string) error {
	name, known := ConfigurationRuntimeRoleName(m.Input.InstallationID, purpose)
	if !known {
		return cfg.ErrInvalid
	}
	return VerifySessionRole(ctx, pool, name)
}
