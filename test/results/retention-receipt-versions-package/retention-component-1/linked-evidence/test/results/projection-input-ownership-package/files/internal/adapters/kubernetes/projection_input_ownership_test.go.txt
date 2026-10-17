package kubernetes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// Pure input ownership only. These original-resource fixtures are synthetic;
// none supplies current native, SQL, provider or effect authority.
func TestProjectionInputOwnershipOwnerConstructor(t *testing.T) {
	root, input, _ := ownerProjectionOriginalInputFixture(t)
	verifier := &ownerProjectionNoEffects{}
	s, err := NewOwnerIdentityProjection(root, verifier, input, OwnerIdentityProviderMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(s.input)
	input.Observation.ImageDigest = strings.Repeat("9", 64)
	input.Observation.Peers[0].Roots[0][0] ^= 1
	input.ConfigurationProbes[0].ConfigMap = "replaced"
	input.CapacityProbe.ServiceAccount.UID = ownerID(14995)
	got, _ := json.Marshal(s.input)
	if !bytes.Equal(want, got) {
		t.Fatal("caller changed retained owner projection input")
	}
	if verifier.calls != 0 {
		t.Fatal("input copy performed credential effects")
	}
}

func TestProjectionInputOwnershipOwnerMaterial(t *testing.T) {
	root, input, state := ownerProjectionOriginalInputFixture(t)
	a := contracts.OwnerIdentityActivation{Input: root.input, RoleRoot: state.OwnerIdentity.RoleRoot, RoleSetupID: state.OwnerIdentity.RoleSetupID, ResourcesCreatedAt: state.CreatedAt, ResourcesUntil: state.Until}
	_, private, now := ownerIdentityPrivateStateFixture(t)
	private.Input, private.OperationID = a.Input, a.RoleSetupID
	for i := range private.Roles {
		role := &private.Roles[i]
		ordinal, _ := contracts.OwnerIdentityRoleOrdinal(role.Purpose)
		role.Receipt = &contracts.PublicRuntimeRoleReceipt{RoleName: fmt.Sprintf("as_%s_own_%02d", strings.ReplaceAll(input.InstallationID, "-", ""), ordinal), RoleOID: uint32(14910 + i), LayoutDigest: a.Input.LayoutDigest}
	}
	roles := contracts.OwnerIdentityRoleSnapshot{State: private, UID: a.RoleRoot.UID, ValidUntil: now.Add(time.Second)}
	material := OwnerIdentityProviderMaterial{Audit: contracts.OwnerStorageCredential{AccessKeyID: "synthetic", SecretAccessKey: "synthetic"}, WrapToken: "wrap", OpenToken: "open", ServerToken: "server", ClientToken: "client"}
	want, _ := json.Marshal(input)
	out, _, data, _, err := ownerIdentityProjectionMaterial(input, a, roles, material, now)
	defer clearRuntimeProjection(data)
	if err != nil {
		t.Fatal(err)
	}
	assertOriginal := func() {
		t.Helper()
		got, _ := json.Marshal(input)
		if !bytes.Equal(want, got) {
			t.Fatal("generated owner projection changed caller input")
		}
	}
	assertOriginal()
	out.Observation.Peers[0].Roots[0][0] ^= 1
	out.ConfigurationProbes[0].ConfigMap = "replaced"
	out.InitialHistoryProbe.Configuration = "replaced"
	assertOriginal()
}

func TestProjectionInputOwnershipCapacityConstructor(t *testing.T) {
	resources, state, _, _ := ownerIdentityActivationFixture(t)
	input, _ := capacityLocalOwnerBindingFixture(t)
	roleInput, _ := publicWorkerProofFixture(t, contracts.PublicRuntimeRoles{InstallationID: resources.initial.InstallationID, InitialClaimID: ownerID(1500), ClusterID: resources.initial.ClusterID, Namespace: resources.initial.Namespace, OwnerConfigurationUID: state.Objects[14].Receipt.UID})
	roles := &PublicRuntimeRoleRoot{input: roleInput}
	bridge := &InitialRuntimeBridge{preparer: resources.preparer, rootUID: resources.rootUID, initial: resources.initial}
	input.InstallationID = resources.initial.InstallationID
	input.Control.ClusterID, input.Control.Namespace = roleInput.ClusterID, roleInput.Namespace
	input.Qualification = json.RawMessage(`{"fixture":"original"}`)
	s, err := NewCapacityRuntimeProjection(bridge, resources, roles, input)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(s.input)
	input.LocalOwner.Source.UID = ownerID(14996)
	input.LocalOwner.Deployment.Observation.Activation.Input.ResourceBinding = strings.Repeat("9", 64)
	input.Qualification[2] = 'x'
	got, _ := json.Marshal(s.input)
	if !bytes.Equal(want, got) {
		t.Fatal("caller changed retained capacity projection input")
	}
}
