package kubernetes

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	fleet "asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
)

func ownerIdentityPrivateStateFixture(t *testing.T) (contracts.OwnerIdentityRoles, contracts.OwnerIdentityRoleState, time.Time) {
	t.Helper()
	_, _, _, a := ownerIdentityActivationFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	v := contracts.OwnerIdentityRoleState{Format: contracts.OwnerIdentityRoleStateFormat, Input: a.Input, OperationID: ownerID(8001), CreatedAt: now.Add(-time.Minute), Until: now.Add(20 * time.Minute)}
	for i, p := range contracts.OwnerIdentityRolePurposes() {
		b := make([]byte, 32)
		for n := range b {
			b[n] = byte(i + 1)
		}
		v.Roles = append(v.Roles, contracts.PublicRuntimeRoleMaterial{Purpose: p, Password: base64.RawURLEncoding.EncodeToString(b), Claim: &contracts.PublicRuntimeRoleClaim{OperationID: ownerID(8100 + i), DatabaseOID: 4100, PostmasterAt: now.Add(-time.Hour), ClaimedAt: now.Add(-30 * time.Second), Until: now.Add(-25 * time.Second)}})
	}
	return a.Input, v, now
}
func cloneOwnerPrivateState(t *testing.T, v contracts.OwnerIdentityRoleState) contracts.OwnerIdentityRoleState {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(b)
	copied, e := contracts.DecodeOwnerIdentityRoleState(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	return copied
}

func TestOwnerIdentityPrivateRoleStateRetainsOriginalAttemptAndEnd(t *testing.T) {
	in, v, now := ownerIdentityPrivateStateFixture(t)
	// Claims have already expired. They remain immutable historical state and
	// cannot be silently discarded to manufacture another SQL CREATE allowance.
	if !ownerIdentityRoleStateValid(in, v, now) {
		t.Fatal("historical original role claims rejected")
	}
	for name, change := range map[string]func(*contracts.OwnerIdentityRoleState){
		"different-resource-root": func(v *contracts.OwnerIdentityRoleState) { v.Input.Resources.UID = ownerID(8990) },
		"new-setup":               func(v *contracts.OwnerIdentityRoleState) { v.Roles[0].Claim.OperationID = v.OperationID },
		"resource-setup-reuse":    func(v *contracts.OwnerIdentityRoleState) { v.Roles[0].Claim.OperationID = in.ResourceSetupID },
		"duplicate-attempt":       func(v *contracts.OwnerIdentityRoleState) { v.Roles[1].Claim.OperationID = v.Roles[0].Claim.OperationID },
		"duplicate-password":      func(v *contracts.OwnerIdentityRoleState) { v.Roles[1].Password = v.Roles[0].Password },
		"zero-password": func(v *contracts.OwnerIdentityRoleState) {
			v.Roles[0].Password = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		},
		"unknown-purpose": func(v *contracts.OwnerIdentityRoleState) { v.Roles[0].Purpose = "routing" },
		"long-claim": func(v *contracts.OwnerIdentityRoleState) {
			v.Roles[0].Claim.Until = v.Roles[0].Claim.ClaimedAt.Add(5*time.Second + time.Microsecond)
		},
		"nanosecond-claim": func(v *contracts.OwnerIdentityRoleState) {
			v.Roles[0].Claim.ClaimedAt = v.Roles[0].Claim.ClaimedAt.Add(time.Nanosecond)
		},
		"future-database": func(v *contracts.OwnerIdentityRoleState) { v.Roles[0].Claim.PostmasterAt = now.Add(time.Second) },
		"past-original-root": func(v *contracts.OwnerIdentityRoleState) {
			v.Roles[0].Claim.ClaimedAt = v.Until.Add(-time.Second)
			v.Roles[0].Claim.Until = v.Until.Add(time.Second)
		},
		"unbounded-root": func(v *contracts.OwnerIdentityRoleState) {
			v.Until = v.CreatedAt.Add(30*time.Minute + time.Microsecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := cloneOwnerPrivateState(t, v)
			change(&x)
			if ownerIdentityRoleStateValid(in, x, now) {
				t.Fatal("mutated original state accepted")
			}
		})
	}
}

func TestOwnerIdentityAcceptedRevisionCannotReplaceOriginalServiceOrTrust(t *testing.T) {
	resources, state, _, _ := ownerIdentityActivationFixture(t)
	object, e := resources.object(state, 14)
	if e != nil {
		t.Fatal(e)
	}
	var wire contracts.OwnerConfiguration
	if e = json.Unmarshal([]byte(object.object.(*core.ConfigMap).Data["owner-pool.json"]), &wire); e != nil {
		t.Fatal(e)
	}
	current := fleet.OwnerConfiguration{Pool: fleet.OwnerPool{InstallationID: wire.InstallationID, ClusterID: wire.ClusterID, IssuerEpoch: wire.IssuerEpoch, Namespace: wire.Namespace.Name, NamespaceUID: wire.Namespace.UID, Service: wire.Service.Name, ServiceUID: wire.Service.UID, Deployment: wire.Deployment.Name, DeploymentUID: wire.Deployment.UID, ServiceAccount: wire.ServiceAccount.Name, AccountUID: wire.ServiceAccount.UID, Port: wire.Port, NativePort: wire.NativePort, NativeBootstrap: wire.NativeBootstrap}, IssuerRoots: wire.IssuerRoots}
	current.Revision.Generation = 5 // source observation can advance; stable provenance cannot.
	if !ownerIdentityOriginalConfiguration(resources, state, current) {
		t.Fatal("same original pool at accepted later revision denied")
	}
	for name, change := range map[string]func(*fleet.OwnerConfiguration){
		"service":           func(c *fleet.OwnerConfiguration) { c.Pool.Service = "other" },
		"service-uid":       func(c *fleet.OwnerConfiguration) { c.Pool.ServiceUID = ownerID(8900) },
		"service-port":      func(c *fleet.OwnerConfiguration) { c.Pool.Port++ },
		"issuer-epoch":      func(c *fleet.OwnerConfiguration) { c.Pool.IssuerEpoch = ownerID(8901) },
		"trust-replacement": func(c *fleet.OwnerConfiguration) { c.IssuerRoots[0] = []byte("different-root") },
		"trust-extension":   func(c *fleet.OwnerConfiguration) { c.IssuerRoots = append(c.IssuerRoots, []byte("additional-root")) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := current.Clone()
			change(&copy)
			if ownerIdentityOriginalConfiguration(resources, state, copy) {
				t.Fatal("accepted source replaced original installation provenance")
			}
		})
	}
}
