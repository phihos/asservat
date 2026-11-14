package kubernetes

import (
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func permissionProjectionFixture(installation string) (contracts.PublicRuntimeRoleSnapshot, contracts.PermissionDeployment) {
	r := contracts.PublicRuntimeRoleSnapshot{UID: ownerID(2101), ObservedAt: time.Now(), ValidUntil: time.Now().Add(5 * time.Second), State: contracts.PublicRuntimeRoleState{
		Input: contracts.PublicRuntimeRoles{InstallationID: installation, ClusterID: ownerID(2102), Namespace: contracts.WorkerObjectReference{Name: "private", UID: ownerID(2103)}}, OperationID: ownerID(2104)}}
	for i, p := range contracts.PermissionProjectionPurposes(true, true, false, false) {
		r.State.Roles = append(r.State.Roles, contracts.PublicRuntimeRoleMaterial{Purpose: p, Password: "synthetic-" + p, Claim: &contracts.PublicRuntimeRoleClaim{OperationID: ownerID(2110 + i)}, Receipt: &contracts.PublicRuntimeRoleReceipt{RoleName: "synthetic-" + p, RoleOID: uint32(300 + i), LayoutDigest: strings.Repeat("5", 64)}})
	}
	c := contracts.PermissionDeployment{Format: contracts.PermissionDeploymentFormat, InstallationID: installation, RootID: ownerID(2105), RoleRootUID: r.UID, RoleSetupID: r.State.OperationID,
		Control: contracts.PermissionControlDeployment{ClusterID: r.State.Input.ClusterID, Namespace: r.State.Input.Namespace}}
	return r, c
}
