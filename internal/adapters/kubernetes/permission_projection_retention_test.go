package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// ADR-195: a retention section adds exactly the four retention logins to the
// permission projection, in order after the permission logins; without it the
// projection keeps its two logins and its public digest.
func TestPermissionProjectionCarriesRetentionLogins(t *testing.T) {
	installation := ownerID(2100)
	r := contracts.PublicRuntimeRoleSnapshot{UID: ownerID(2101), ObservedAt: time.Now(), ValidUntil: time.Now().Add(5 * time.Second), State: contracts.PublicRuntimeRoleState{
		Input: contracts.PublicRuntimeRoles{InstallationID: installation, ClusterID: ownerID(2102), Namespace: contracts.WorkerObjectReference{Name: "private", UID: ownerID(2103)}}, OperationID: ownerID(2104)}}
	for i, p := range contracts.PermissionProjectionPurposes(true) {
		r.State.Roles = append(r.State.Roles, contracts.PublicRuntimeRoleMaterial{Purpose: p, Password: "synthetic-" + p, Claim: &contracts.PublicRuntimeRoleClaim{OperationID: ownerID(2110 + i)}, Receipt: &contracts.PublicRuntimeRoleReceipt{RoleName: "synthetic-" + p, RoleOID: uint32(300 + i), LayoutDigest: strings.Repeat("5", 64)}})
	}
	c := contracts.PermissionDeployment{Format: contracts.PermissionDeploymentFormat, InstallationID: installation, RootID: ownerID(2105), RoleRootUID: r.UID, RoleSetupID: r.State.OperationID,
		Control: contracts.PermissionControlDeployment{ClusterID: r.State.Input.ClusterID, Namespace: r.State.Input.Namespace}}
	plain, plainDigest, err := permissionProjectionMaterial(c, r)
	if err != nil || len(plain) != 4 {
		t.Fatal("permission-only projection", err, len(plain))
	}
	clearRuntimeProjection(plain)
	c.Retention = &contracts.RetentionDeployment{Guard: contracts.OwnerDeploymentGuard{Name: contracts.RetentionGuardName(installation)}}
	data, digest, err := permissionProjectionMaterial(c, r)
	if err != nil || len(data) != 8 || digest == plainDigest {
		t.Fatal("retention projection", err, len(data))
	}
	defer clearRuntimeProjection(data)
	var m contracts.PermissionCredentialManifest
	if json.Unmarshal(data[contracts.PermissionCredentialManifestFile], &m) != nil || len(m.Roles) != 6 || m.Roles[2].Purpose != "retention-source" || m.Roles[5].Purpose != "retention-lifecycle-audit" {
		t.Fatal("manifest order", m.Roles)
	}
	for _, p := range contracts.PublicRuntimeRetentionPurposes() {
		if len(data["sql-"+p+".json"]) == 0 {
			t.Fatal("missing retention login", p)
		}
	}
}
