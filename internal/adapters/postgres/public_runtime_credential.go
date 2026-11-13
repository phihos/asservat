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

// VerifyPublisherRuntimeCredential checks one login of the publisher
// compartment against its own exact projection manifest (ADR-181).
func VerifyPublisherRuntimeCredential(ctx context.Context, pool *pgxpool.Pool, m contracts.PublicRuntimeCredentialManifest, purpose string) error {
	return verifyRuntimeCredential(ctx, pool, m, purpose, contracts.PublicRuntimePublisherPurposes())
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
