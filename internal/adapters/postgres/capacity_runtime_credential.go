package postgres

import (
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func capacityRoleHistoricalClaim(v contracts.PublicRuntimeRoleClaim, now time.Time) bool {
	return authorization.UUID(v.OperationID) && v.DatabaseOID != 0 && v.PostmasterAt.Year() >= 2020 &&
		!v.PostmasterAt.After(v.ClaimedAt) && v.ClaimedAt.Year() >= 2020 && !v.ClaimedAt.After(now) &&
		v.PostmasterAt.Nanosecond()%1000 == 0 && v.ClaimedAt.Nanosecond()%1000 == 0 && v.Until.Nanosecond()%1000 == 0 &&
		v.Until.After(v.ClaimedAt) && !v.Until.After(v.ClaimedAt.Add(5*time.Second))
}

// Static validation deliberately recognizes only the two permanent capacity
// ordinals. Recognition cannot make an unimplemented grant layout creatable;
// actual verification below additionally requires the compiled inventory.
func ValidateCapacityCredentialManifest(v contracts.CapacityCredentialManifest, now time.Time) error {
	if v.Format != contracts.CapacityCredentialManifestFormat || v.Input.Format != contracts.PublicRuntimeRolesFormat ||
		!authorization.UUID(v.Input.InstallationID) || !authorization.UUID(v.Input.InitialClaimID) || !authorization.UUID(v.Input.ClusterID) ||
		!authorization.UUID(v.Input.OwnerConfigurationUID) || !authorization.UUID(v.Input.Namespace.UID) || !identity.Text(v.Input.Namespace.Name, 63) ||
		!authorization.UUID(v.RootUID) || !authorization.UUID(v.SetupID) || len(v.Roles) != 2 {
		return cfg.ErrInvalid
	}
	layout, err := hex.DecodeString(v.Input.LayoutDigest)
	if err != nil || len(layout) != 32 || hex.EncodeToString(layout) != v.Input.LayoutDigest || v.Input.LayoutDigest == strings.Repeat("0", 64) {
		return cfg.ErrInvalid
	}
	c := v.Capacity
	if c.Format != contracts.CapacityRootSetupFormat || c.InstallationID != v.Input.InstallationID || c.InitialClaimID != v.Input.InitialClaimID ||
		c.RoleRootUID != v.RootUID || c.RoleSetupID != v.SetupID || !authorization.UUID(c.PermissionRootID) ||
		!capacityRoleHistoricalClaim(contracts.PublicRuntimeRoleClaim{OperationID: c.OperationID, DatabaseOID: c.DatabaseOID, PostmasterAt: c.PostmasterAt, ClaimedAt: c.ClaimedAt, Until: c.Until}, now) {
		return cfg.ErrInvalid
	}
	inputDigest, err := hex.DecodeString(c.InputDigest)
	if err != nil || len(inputDigest) != 32 || hex.EncodeToString(inputDigest) != c.InputDigest || c.InputDigest == strings.Repeat("0", 64) || c.OperationID == v.SetupID {
		return cfg.ErrInvalid
	}
	claims := map[string]bool{v.SetupID: true, c.OperationID: true}
	roles := map[uint32]bool{}
	for i, purpose := range contracts.CapacityRuntimePurposes() {
		r := v.Roles[i]
		name := "as_" + strings.ReplaceAll(v.Input.InstallationID, "-", "") + "_pub_" + []string{"70", "71"}[i]
		if r.Purpose != purpose || r.Receipt.RoleName != name || r.Receipt.RoleOID == 0 || r.Receipt.RoleOID == 10 || roles[r.Receipt.RoleOID] ||
			r.Receipt.LayoutDigest != v.Input.LayoutDigest || !capacityRoleHistoricalClaim(r.Claim, now) || claims[r.Claim.OperationID] ||
			r.Claim.DatabaseOID != c.DatabaseOID || !r.Claim.PostmasterAt.Equal(c.PostmasterAt) || r.Claim.ClaimedAt.After(c.ClaimedAt) {
			return cfg.ErrInvalid
		}
		claims[r.Claim.OperationID], roles[r.Receipt.RoleOID] = true, true
	}
	return nil
}

// VerifyCapacityRuntimeCredential uses the actual70/71 login and original
// protected manifest. It cannot provision or repair roles, roots or grants.
// Historical role claims are compared by identity; all current effect and
// recovery observations retain their own independent original intervals.
func VerifyCapacityRuntimeCredential(ctx context.Context, pool *pgxpool.Pool, manifest contracts.CapacityCredentialManifest, purpose string, qualification app.CapacityQualification) error {
	if !slices.Contains(contracts.CapacityRuntimePurposes(), purpose) {
		return cfg.ErrInvalid
	}
	name, known := PublicRuntimeRoleName(manifest.Input.InstallationID, purpose)
	if !known {
		return cfg.ErrInvalid
	}
	return VerifyRuntimeLogin(ctx, pool, name)
}
