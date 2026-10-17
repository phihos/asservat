package kubernetes

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func capacityProjectionMaterialFixture() (contracts.CapacityDeployment, contracts.PublicRuntimeRoleSnapshot) {
	installation, state, now := capacityProjectionStateFixture()
	setup := state.CapacityProjection.Setup
	r := contracts.PublicRuntimeRoleSnapshot{UID: setup.RoleRootUID, ObservedAt: now, ValidUntil: now.Add(5 * time.Second), State: contracts.PublicRuntimeRoleState{Input: contracts.PublicRuntimeRoles{InstallationID: installation, InitialClaimID: setup.InitialClaimID, ClusterID: ownerID(2000), Namespace: contracts.WorkerObjectReference{Name: "private", UID: ownerID(2001)}}, OperationID: setup.RoleSetupID, CreatedAt: state.CreatedAt, Until: state.Until,
		MAC:           contracts.PublicAuditKeyMaterial{InputVersion: "input/v1", AccountVersion: setup.RoleSetupID + "-account/v1", InputKey: bytes.Repeat([]byte{91}, 32), AccountKey: bytes.Repeat([]byte{92}, 32)},
		CapacitySetup: &contracts.CapacityRootSetupClaim{OperationID: setup.OperationID, PermissionRootID: setup.PermissionRootID, InputDigest: setup.InputDigest, DatabaseOID: setup.DatabaseOID, PostmasterAt: setup.PostmasterAt, ClaimedAt: setup.ClaimedAt, Until: setup.Until, Receipt: &setup}}}
	for i, p := range contracts.CapacitySetupRolePurposes() {
		r.State.Roles = append(r.State.Roles, contracts.PublicRuntimeRoleMaterial{Purpose: p, Password: "synthetic-" + p, Claim: &contracts.PublicRuntimeRoleClaim{OperationID: ownerID(2010 + i)}, Receipt: &contracts.PublicRuntimeRoleReceipt{RoleName: "synthetic-" + p, RoleOID: uint32(200 + i), LayoutDigest: strings.Repeat("5", 64)}})
	}
	c := contracts.CapacityDeployment{Format: contracts.CapacityDeploymentFormat, InstallationID: installation, PermissionRootID: setup.PermissionRootID, RoleRootUID: r.UID, RoleSetupID: r.State.OperationID, AccountVersion: r.State.MAC.AccountVersion, Control: contracts.CapacityControlDeployment{ClusterID: r.State.Input.ClusterID, Namespace: r.State.Input.Namespace}, Qualification: json.RawMessage(`{}`)}
	return c, r
}

func TestCapacityProjectionOnlyDedicatedMaterialAndPublicDigest(t *testing.T) {
	c, r := capacityProjectionMaterialFixture()
	data, digest, e := capacityProjectionMaterial(c, r)
	if e != nil || len(data) != 5 || !capacitySetupDigest(digest) {
		t.Fatal("fixed projection unavailable", e)
	}
	defer clearRuntimeProjection(data)
	for _, name := range []string{contracts.CapacityDeploymentFile, contracts.CapacityCredentialManifestFile, contracts.CaptureAccountKeyFile, "sql-capacity.json", "sql-capacity-capture.json"} {
		if len(data[name]) == 0 {
			t.Fatal("missing fixed file", name)
		}
	}
	var m contracts.CapacityCredentialManifest
	if json.Unmarshal(data[contracts.CapacityCredentialManifestFile], &m) != nil || len(m.Roles) != 2 || m.Roles[0].Purpose != "capacity" || m.Roles[1].Purpose != "capacity-capture" {
		t.Fatal("other compartment entered manifest")
	}
	var key contracts.CaptureAccountKey
	if json.Unmarshal(data[contracts.CaptureAccountKeyFile], &key) != nil || !bytes.Equal(key.Key, r.State.MAC.AccountKey) || bytes.Equal(key.Key, r.State.MAC.InputKey) {
		t.Fatal("wrong account-only seed")
	}
	for i := range r.State.Roles {
		r.State.Roles[i].Password += "-different"
	}
	r.State.MAC.AccountKey = bytes.Repeat([]byte{93}, 32)
	r.State.MAC.InputKey = bytes.Repeat([]byte{94}, 32)
	other, same, e := capacityProjectionMaterial(c, r)
	if e != nil {
		t.Fatal(e)
	}
	defer clearRuntimeProjection(other)
	if same != digest || bytes.Equal(data["sql-capacity.json"], other["sql-capacity.json"]) || bytes.Equal(data[contracts.CaptureAccountKeyFile], other[contracts.CaptureAccountKeyFile]) {
		t.Fatal("public digest contains a secret-payload fingerprint or material silently ignored")
	}
	m.Capacity.DatabaseOID++
	if CapacityRuntimePublicDigest(c, m) == digest {
		t.Fatal("original SQL incarnation omitted from public binding")
	}
}

func TestCapacityProjectionMaterialRejectsIncompleteAndSubstitutedSetup(t *testing.T) {
	for _, mode := range []string{"missing-receipt", "wrong-root", "wrong-installation", "changed-setup", "changed-account-version", "duplicate-capacity-role", "missing-role", "oversize-public"} {
		t.Run(mode, func(t *testing.T) {
			c, r := capacityProjectionMaterialFixture()
			switch mode {
			case "missing-receipt":
				r.State.CapacitySetup.Receipt = nil
			case "wrong-root":
				c.RoleRootUID = ownerID(2200)
			case "wrong-installation":
				c.InstallationID = ownerID(2200)
			case "changed-setup":
				r.State.CapacitySetup.Receipt.DatabaseOID++
			case "changed-account-version":
				c.AccountVersion += "-new"
			case "duplicate-capacity-role":
				for _, role := range r.State.Roles {
					if role.Purpose == "capacity" {
						r.State.Roles = append(r.State.Roles, role)
						break
					}
				}
			case "missing-role":
				r.State.Roles = r.State.Roles[:len(r.State.Roles)-1]
			case "oversize-public":
				c.Qualification = json.RawMessage(`{"synthetic":"` + strings.Repeat("x", contracts.CapacityDeploymentMaxBytes) + `"}`)
			}
			data, _, e := capacityProjectionMaterial(c, r)
			if e == nil || data != nil {
				clearRuntimeProjection(data)
				t.Fatal("unqualified material projected")
			}
		})
	}
}

// This measures the real closed encoder with the complete typed original owner
// carrier. The surrounding setup remains synthetic and confers no authority.
func TestCapacityProjectionWholeOwnerCarrierKeepsOriginalByteLimit(t *testing.T) {
	c, r := capacityProjectionMaterialFixture()
	original, _ := capacityLocalOwnerBindingFixture(t)
	c.LocalOwner = original.LocalOwner
	base, err := json.Marshal(c)
	if err != nil || len(base) >= contracts.CapacityDeploymentMaxBytes {
		t.Fatal("complete original carrier exceeds closed projection limit", len(base), err)
	}
	t.Logf("synthetic complete carrier deployment bytes=%d maximum=%d", len(base), contracts.CapacityDeploymentMaxBytes)
	material, _, err := capacityProjectionMaterial(c, r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded contracts.CapacityDeployment
	err = json.Unmarshal(material[contracts.CapacityDeploymentFile], &decoded)
	clearRuntimeProjection(material)
	if err != nil || !equalJSON(decoded.LocalOwner, c.LocalOwner) {
		t.Fatal("original carrier lost in encoder", err)
	}
	// Pin the exact final JSON boundary, including repeated provenance and HTML
	// escaping. There is no truncation or separate uncounted carrier allowance.
	c.Qualification = json.RawMessage(`{"synthetic":""}`)
	base, err = json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	remaining := contracts.CapacityDeploymentMaxBytes - len(base)
	if remaining < 0 {
		t.Fatal("carrier exceeds original cap")
	}
	c.Qualification = json.RawMessage(`{"synthetic":"` + strings.Repeat("x", remaining) + `"}`)
	material, _, err = capacityProjectionMaterial(c, r)
	if err != nil || len(material[contracts.CapacityDeploymentFile]) != contracts.CapacityDeploymentMaxBytes {
		t.Fatal("exact closed encoder boundary rejected", err)
	}
	clearRuntimeProjection(material)
	c.Qualification = json.RawMessage(`{"synthetic":"` + strings.Repeat("x", remaining+1) + `"}`)
	material, _, err = capacityProjectionMaterial(c, r)
	if err == nil || material != nil {
		clearRuntimeProjection(material)
		t.Fatal("oversized full deployment accepted")
	}
	c.Qualification = json.RawMessage(`{"synthetic":"` + strings.Repeat("<", remaining/6+1) + `"}`)
	material, _, err = capacityProjectionMaterial(c, r)
	if err == nil || material != nil {
		clearRuntimeProjection(material)
		t.Fatal("escaped encoded bytes escaped original bound")
	}
}
