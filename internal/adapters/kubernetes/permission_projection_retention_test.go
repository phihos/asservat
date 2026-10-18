package kubernetes

import (
	"encoding/json"
	"slices"
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
	r, c := permissionProjectionFixture(installation)
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

func permissionProjectionFixture(installation string) (contracts.PublicRuntimeRoleSnapshot, contracts.PermissionDeployment) {
	r := contracts.PublicRuntimeRoleSnapshot{UID: ownerID(2101), ObservedAt: time.Now(), ValidUntil: time.Now().Add(5 * time.Second), State: contracts.PublicRuntimeRoleState{
		Input: contracts.PublicRuntimeRoles{InstallationID: installation, ClusterID: ownerID(2102), Namespace: contracts.WorkerObjectReference{Name: "private", UID: ownerID(2103)}}, OperationID: ownerID(2104)}}
	for i, p := range contracts.PermissionProjectionPurposes(true, true) {
		r.State.Roles = append(r.State.Roles, contracts.PublicRuntimeRoleMaterial{Purpose: p, Password: "synthetic-" + p, Claim: &contracts.PublicRuntimeRoleClaim{OperationID: ownerID(2110 + i)}, Receipt: &contracts.PublicRuntimeRoleReceipt{RoleName: "synthetic-" + p, RoleOID: uint32(300 + i), LayoutDigest: strings.Repeat("5", 64)}})
	}
	c := contracts.PermissionDeployment{Format: contracts.PermissionDeploymentFormat, InstallationID: installation, RootID: ownerID(2105), RoleRootUID: r.UID, RoleSetupID: r.State.OperationID,
		Control: contracts.PermissionControlDeployment{ClusterID: r.State.Input.ClusterID, Namespace: r.State.Input.Namespace}}
	return r, c
}

// ADR-204 decision 7: a worker configuration section adds exactly its two
// logins after the retention logins. Without it the deployment bytes, the
// public digest and the projected files stay those of the retention layout,
// so an existing projection keeps its claim.
func TestPermissionProjectionCarriesWorkerConfigurationLogins(t *testing.T) {
	installation := ownerID(2100)
	r, c := permissionProjectionFixture(installation)
	c.Retention = &contracts.RetentionDeployment{Guard: contracts.OwnerDeploymentGuard{Name: contracts.RetentionGuardName(installation)}}
	plain, plainDigest, err := permissionProjectionMaterial(c, r)
	if err != nil || len(plain) != 8 || strings.Contains(string(plain[contracts.PermissionDeploymentFile]), "workerConfiguration") {
		t.Fatal("projection without the section", err, len(plain))
	}
	clearRuntimeProjection(plain)
	c.WorkerConfiguration = &contracts.WorkerConfigurationDeployment{Namespace: contracts.WorkerObjectReference{Name: "downloads", UID: ownerID(2106)}, Source: contracts.WorkerObjectReference{Name: "worker-profile", UID: ownerID(2107)},
		Guard:        contracts.OwnerDeploymentGuard{Name: "worker-profile-guard", PolicyUID: ownerID(2108), PolicyGeneration: 1, BindingUID: ownerID(2109), BindingResourceVersion: "4", Administrators: []contracts.OwnerDeploymentActor{{Kind: "Group", Name: "installers"}}},
		AuditTransit: contracts.OwnerPublicTransit{Mount: "transit", Key: "worker-configuration-audit"}}
	// The immutable projection never carries a section the hub-worker would
	// refuse: workers outside the hub namespace, a pinned guard of its own.
	if !WorkerConfigurationSectionValid(c) {
		t.Fatal("valid worker configuration section refused")
	}
	for name, mutate := range map[string]func(*contracts.WorkerConfigurationDeployment){
		"hub namespace":     func(v *contracts.WorkerConfigurationDeployment) { v.Namespace = c.Control.Namespace },
		"unpinned guard":    func(v *contracts.WorkerConfigurationDeployment) { v.Guard.BindingUID = "" },
		"no administrators": func(v *contracts.WorkerConfigurationDeployment) { v.Guard.Administrators = nil },
		"duplicate administrator": func(v *contracts.WorkerConfigurationDeployment) {
			v.Guard.Administrators = append(v.Guard.Administrators, v.Guard.Administrators[0])
		},
		"transit key path": func(v *contracts.WorkerConfigurationDeployment) { v.AuditTransit.Key = "keys/audit" },
	} {
		changed := *c.WorkerConfiguration
		changed.Guard.Administrators = slices.Clone(changed.Guard.Administrators)
		mutate(&changed)
		if WorkerConfigurationSectionValid(contracts.PermissionDeployment{Control: c.Control, WorkerConfiguration: &changed}) {
			t.Fatal("accepted:", name)
		}
	}
	data, digest, err := permissionProjectionMaterial(c, r)
	if err != nil || len(data) != 10 || digest == plainDigest {
		t.Fatal("worker configuration projection", err, len(data))
	}
	defer clearRuntimeProjection(data)
	var m contracts.PermissionCredentialManifest
	if json.Unmarshal(data[contracts.PermissionCredentialManifestFile], &m) != nil || len(m.Roles) != 8 || m.Roles[5].Purpose != "retention-lifecycle-audit" || m.Roles[6].Purpose != "worker-config-observe" || m.Roles[7].Purpose != "worker-config-audit" {
		t.Fatal("manifest order", m.Roles)
	}
	for _, p := range contracts.PublicRuntimeWorkerConfigurationPurposes() {
		if len(data["sql-"+p+".json"]) == 0 {
			t.Fatal("missing worker configuration login", p)
		}
	}
	// The hub-worker Pod projects both files from the same optional Secret.
	p, workerInstallation, _, _ := providerWorkerPlan(t)
	w, err := BuildInstalledHubWorkerWorkload(p, workerInstallation)
	if err != nil {
		t.Fatal(err)
	}
	projected := map[string]bool{}
	for _, source := range w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources {
		if source.Secret != nil && source.Secret.Name == contracts.PermissionRuntimeProjectionName(workerInstallation) && *source.Secret.Optional {
			for _, item := range source.Secret.Items {
				projected[item.Key] = item.Path == contracts.PermissionWorkerProjectionDirectory+"/"+item.Key
			}
		}
	}
	for name := range data {
		if !projected[name] {
			t.Fatal("permission projection file not mounted", name)
		}
	}
}
