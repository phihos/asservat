package kubernetes

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestCapacitySetupIncompleteRoleInventoryCannotClaim(t *testing.T) {
	f := newPublicRoleRootFixture(t, false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	old, err := f.root.OpenPublicRuntimeRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := f.writes.Load()
	_, fresh, err := f.root.ClaimCapacityRootSetup(ctx, old.UID, old.State.OperationID, ownerID(50), strings.Repeat("1", 64), 100, time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute))
	if err == nil || fresh || f.writes.Load() != before {
		t.Fatal("partial inventory consumed capacity setup claim")
	}
}

// Pure retained-state validation; actual API/CAS claim tests require the final
// qualified full role inventory. No fake role receipt confers SQL authority.
func TestCapacitySetupOriginalClaimAndReceiptAreClosed(t *testing.T) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	fixture := func() contracts.PublicRuntimeRoleState {
		v := contracts.PublicRuntimeRoleState{Input: contracts.PublicRuntimeRoles{InstallationID: ownerID(1), InitialClaimID: ownerID(2)}, OperationID: ownerID(3), CreatedAt: n.Add(-time.Minute), Until: n.Add(time.Minute)}
		for i, p := range contracts.CapacitySetupRolePurposes() {
			v.Roles = append(v.Roles, contracts.PublicRuntimeRoleMaterial{Purpose: p, Claim: &contracts.PublicRuntimeRoleClaim{OperationID: ownerID(i + 10)}, Receipt: &contracts.PublicRuntimeRoleReceipt{RoleOID: uint32(i + 100)}})
		}
		v.CapacitySetup = &contracts.CapacityRootSetupClaim{OperationID: ownerID(30), PermissionRootID: ownerID(31), InputDigest: strings.Repeat("1", 64), DatabaseOID: 100, PostmasterAt: n.Add(-time.Hour), ClaimedAt: n, Until: n.Add(5 * time.Second)}
		c := v.CapacitySetup
		c.Receipt = &contracts.CapacityRootSetupReceipt{Format: contracts.CapacityRootSetupFormat, OperationID: c.OperationID, InstallationID: v.Input.InstallationID, InitialClaimID: v.Input.InitialClaimID, PermissionRootID: c.PermissionRootID, RoleRootUID: ownerID(40), RoleSetupID: v.OperationID, InputDigest: c.InputDigest, DatabaseOID: c.DatabaseOID, PostmasterAt: c.PostmasterAt, ClaimedAt: c.ClaimedAt, Until: c.Until}
		return v
	}
	for _, name := range []string{"valid", "completed-later", "missing-role", "missing-role-receipt", "duplicate-operation", "future-claim", "renewed-until", "changed-database", "changed-root", "changed-digest", "changed-receipt-until", "zero-digest"} {
		t.Run(name, func(t *testing.T) {
			v := fixture()
			now := n
			switch name {
			case "completed-later":
				now = n.Add(time.Hour)
			case "missing-role":
				v.Roles = v.Roles[:len(v.Roles)-1]
			case "missing-role-receipt":
				v.Roles[0].Receipt = nil
			case "duplicate-operation":
				v.CapacitySetup.OperationID = v.Roles[0].Claim.OperationID
			case "future-claim":
				v.CapacitySetup.ClaimedAt = n.Add(time.Second)
			case "renewed-until":
				v.CapacitySetup.Until = n.Add(6 * time.Second)
			case "changed-database":
				v.CapacitySetup.Receipt.DatabaseOID++
			case "changed-root":
				v.CapacitySetup.Receipt.PermissionRootID = ownerID(41)
			case "changed-digest":
				v.CapacitySetup.Receipt.InputDigest = strings.Repeat("2", 64)
			case "changed-receipt-until":
				v.CapacitySetup.Receipt.Until = v.CapacitySetup.Until.Add(time.Microsecond)
			case "zero-digest":
				v.CapacitySetup.InputDigest = strings.Repeat("0", 64)
			}
			want := name == "valid" || name == "completed-later"
			if capacitySetupStateValid(v, now) != want {
				t.Fatal("original setup identity/interval validation differs")
			}
		})
	}
}

func TestCapacitySetupOmissionPreservesOldRoleStateBytes(t *testing.T) {
	// Decode/reencode the previous zero-value shape, including its explicit
	// fields, without appending a capability to an older retained root.
	v := contracts.PublicRuntimeRoleState{}
	raw, err := json.Marshal(v)
	if err != nil || strings.Contains(string(raw), "capacitySetup") {
		t.Fatal("omitted setup changed legacy bytes")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("invalid encoded state")
	}
	delete(fields, "capacitySetup")
	if len(fields) != 7 {
		t.Fatal("legacy role state shape changed")
	}
}
