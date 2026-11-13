package postgres

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func captureCleanupDigest(v string) bool {
	b, err := hex.DecodeString(v)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == v && v != strings.Repeat("0", 64)
}

func captureCleanupHistoricalClaim(c contracts.PublicRuntimeRoleClaim, now time.Time) bool {
	return authorization.UUID(c.OperationID) && c.DatabaseOID != 0 && c.PostmasterAt.Year() >= 2020 &&
		c.ClaimedAt.Year() >= 2020 && !c.PostmasterAt.After(c.ClaimedAt) && !c.ClaimedAt.After(now) &&
		c.PostmasterAt.Nanosecond()%1000 == 0 && c.ClaimedAt.Nanosecond()%1000 == 0 && c.Until.Nanosecond()%1000 == 0 &&
		c.Until.After(c.ClaimedAt) && c.Until.Sub(c.ClaimedAt) <= 5*time.Second
}

// This closed manifest contains only the three worker cleanup credentials.
// Original SQL and worker receipts are historical provenance, not a fresh
// configuration or recovery observation and not permission to repair roles.
func ValidateCaptureCleanupCredentialManifest(m contracts.CaptureCleanupCredentialManifest, now time.Time) error {
	i, setup := m.Input, m.CaptureSetup
	if m.Format != contracts.CaptureCleanupManifestFormat || i.Format != contracts.PublicRuntimeRolesFormat ||
		!authorization.UUID(i.InstallationID) || !authorization.UUID(i.InitialClaimID) || !authorization.UUID(i.ClusterID) ||
		!authorization.UUID(i.Namespace.UID) || !identity.Text(i.Namespace.Name, 63) || !authorization.UUID(i.OwnerConfigurationUID) || !captureCleanupDigest(i.LayoutDigest) ||
		!authorization.UUID(m.RootUID) || !authorization.UUID(m.SetupID) || (i.Worker.WorkerLayout != contracts.HubWorkerInstalledLayout && i.Worker.WorkerLayout != contracts.HubWorkerProviderInstalledLayout) ||
		!authorization.UUID(i.Worker.Resources.UID) || !identity.Text(i.Worker.Resources.Name, 253) || !authorization.UUID(i.Worker.ResourceSetupID) || !captureCleanupDigest(i.Worker.ResourceBinding) ||
		setup.Format != contracts.CapacityRootSetupFormat || setup.InstallationID != i.InstallationID ||
		setup.InitialClaimID != i.InitialClaimID || setup.RoleRootUID != m.RootUID || setup.RoleSetupID != m.SetupID ||
		!authorization.UUID(setup.PermissionRootID) || !captureCleanupDigest(setup.InputDigest) ||
		!captureCleanupHistoricalClaim(contracts.PublicRuntimeRoleClaim{OperationID: setup.OperationID, DatabaseOID: setup.DatabaseOID, PostmasterAt: setup.PostmasterAt, ClaimedAt: setup.ClaimedAt, Until: setup.Until}, now) || setup.OperationID == m.SetupID {
		return cfg.ErrInvalid
	}
	purposes := contracts.PublicRuntimeCaptureCleanupPurposes()
	if len(m.Roles) != len(purposes) {
		return cfg.ErrInvalid
	}
	operations, oids := map[string]bool{m.SetupID: true, setup.OperationID: true}, map[uint32]bool{}
	for n, purpose := range purposes {
		r := m.Roles[n]
		name, known := PublicRuntimeRoleName(i.InstallationID, purpose)
		if !known || r.Purpose != purpose || r.Receipt.RoleName != name || r.Receipt.RoleOID == 0 || r.Receipt.RoleOID == 10 ||
			oids[r.Receipt.RoleOID] || operations[r.Claim.OperationID] || r.Receipt.LayoutDigest != i.LayoutDigest ||
			!captureCleanupHistoricalClaim(r.Claim, now) || r.Claim.DatabaseOID != setup.DatabaseOID ||
			!r.Claim.PostmasterAt.Equal(setup.PostmasterAt) || r.Claim.ClaimedAt.After(setup.ClaimedAt) {
			return cfg.ErrInvalid
		}
		operations[r.Claim.OperationID], oids[r.Receipt.RoleOID] = true, true
	}
	return nil
}

// Each call authenticates one original fixed role, compares its exact OID,
// comment, direct and ambient privileges and checks its private root pin.
// Current recovery is read independently by the lifecycle facet before effects.
func VerifyCaptureCleanupCredential(ctx context.Context, pool *pgxpool.Pool, m contracts.CaptureCleanupCredentialManifest, purpose string) error {
	name, known := PublicRuntimeRoleName(m.Input.InstallationID, purpose)
	private := map[string]string{"capture-cleanup": "cleanup", "capture-verifier": "verifier", "capture-finalizer": "finalizer"}[purpose]
	if !known || private == "" {
		return cfg.ErrInvalid
	}
	if err := VerifyRuntimeLogin(ctx, pool, name); err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var exact bool
	if pool.QueryRow(call, `SELECT public.capture_audit_role_ok($1::uuid,$2::text)`, m.CaptureSetup.PermissionRootID, private).Scan(&exact) != nil || !exact || call.Err() != nil {
		return cfg.ErrDenied
	}
	return nil
}
