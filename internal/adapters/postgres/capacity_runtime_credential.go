package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
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
	if ctx == nil || ctx.Err() != nil || pool == nil || ValidateCapacityCredentialManifest(manifest, time.Now()) != nil ||
		manifest.Input.LayoutDigest != PublicRuntimeRoleLayoutDigest() || !qualification.Valid() ||
		qualification.RootBacking.RootID != manifest.Capacity.PermissionRootID || qualification.RootBacking.InstallationID != manifest.Input.InstallationID ||
		qualification.RootBacking.AccountVersion != manifest.SetupID+"-account/v1" || !app.ValidateRootBackingInput(qualification.RootBacking) {
		return cfg.ErrInvalid
	}
	index := -1
	for i, p := range contracts.CapacityRuntimePurposes() {
		if p == purpose {
			index = i
		}
	}
	if index < 0 {
		return cfg.ErrInvalid
	}
	selected := manifest.Roles[index]
	name, known := PublicRuntimeRoleName(manifest.Input.InstallationID, purpose)
	grants, fixed := publicRuntimeRoleGrants(purpose)
	if !known || !fixed || name != selected.Receipt.RoleName || pool.Config().ConnConfig.User != name || pool.Config().MaxConns != 1 || pool.Config().MinConns != 0 {
		return cfg.ErrDenied
	}
	started := capacityObservedMicro(time.Now().UTC())
	until := started.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	until = until.Truncate(time.Microsecond)
	call, end := context.WithDeadline(ctx, until)
	defer end()
	var exact bool
	if err := pool.QueryRow(call, `SELECT current_user=session_user AND oid=$1 FROM pg_roles WHERE rolname=session_user`, selected.Receipt.RoleOID).Scan(&exact); err != nil || !exact {
		return cfg.ErrDenied
	}
	verifier := &PublicRuntimeSQLRoles{input: manifest.Input}
	snapshot := contracts.PublicRuntimeRoleSnapshot{UID: manifest.RootUID, State: contracts.PublicRuntimeRoleState{Input: manifest.Input, OperationID: manifest.SetupID}}
	provenance, err := json.Marshal(verifier.provenance(snapshot, purpose, selected.Claim))
	if err != nil {
		return cfg.ErrInvalid
	}
	if _, err = verifyFixedRuntimeRole(call, pool, name, 3, manifest.Input.LayoutDigest, &selected.Receipt, provenance, grants); err != nil {
		return err
	}
	receipt, err := json.Marshal(manifest.Capacity)
	if err != nil {
		return cfg.ErrInvalid
	}
	qualified, err := json.Marshal(qualification)
	if err != nil {
		return cfg.ErrInvalid
	}
	ledger, err := New(call, pool)
	if err != nil {
		return cfg.ErrUnavailable
	}
	var narrow *time.Timer
	var joined chan struct{}
	defer func() {
		if narrow != nil && !narrow.Stop() {
			<-joined
		}
	}()
	err = ledger.transaction(call, func(q *custodydb.Queries) error {
		untilSQL, err := q.ReadCapacityRuntimeScope(call, custodydb.ReadCapacityRuntimeScopeParams{RootID: id(manifest.Capacity.PermissionRootID), ExpectedValue: receipt, QualificationValue: qualified, ObservedAt: ts(started), FreshUntil: ts(until)})
		if err != nil || !untilSQL.Valid || untilSQL.Time.After(until) || !time.Now().Before(untilSQL.Time) {
			return cfg.ErrUnavailable
		}
		until = untilSQL.Time
		joined = make(chan struct{})
		narrow = time.AfterFunc(time.Until(until), func() { end(); close(joined) })
		return call.Err()
	})
	if err != nil || call.Err() != nil || !time.Now().Before(until) {
		return cfg.ErrUnavailable
	}
	return nil
}
