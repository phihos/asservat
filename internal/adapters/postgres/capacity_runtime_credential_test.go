package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
)

func capacityRuntimeManifestFixture() contracts.CapacityCredentialManifest {
	id := func(n int) string { return fmt.Sprintf("90000000-0000-4000-8000-%012d", n) }
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	p := contracts.PublicRuntimeRoles{Format: contracts.PublicRuntimeRolesFormat, InstallationID: id(1), InitialClaimID: id(2), ClusterID: id(3), OwnerConfigurationUID: id(4), Namespace: contracts.WorkerObjectReference{Name: "private", UID: id(5)}, LayoutDigest: strings.Repeat("a", 64)}
	m := contracts.CapacityCredentialManifest{Format: contracts.CapacityCredentialManifestFormat, Input: p, RootUID: id(6), SetupID: id(7),
		Capacity: contracts.CapacityRootSetupReceipt{Format: contracts.CapacityRootSetupFormat, OperationID: id(8), InstallationID: p.InstallationID, InitialClaimID: p.InitialClaimID, PermissionRootID: id(9), RoleRootUID: id(6), RoleSetupID: id(7), InputDigest: strings.Repeat("b", 64), DatabaseOID: 1234, PostmasterAt: at.Add(-time.Hour), ClaimedAt: at.Add(time.Minute), Until: at.Add(time.Minute + 5*time.Second)}}
	for i, purpose := range contracts.CapacityRuntimePurposes() {
		m.Roles = append(m.Roles, contracts.PublicRuntimeCredentialProof{Purpose: purpose,
			Claim:   contracts.PublicRuntimeRoleClaim{OperationID: id(10 + i), DatabaseOID: m.Capacity.DatabaseOID, PostmasterAt: m.Capacity.PostmasterAt, ClaimedAt: at, Until: at.Add(5 * time.Second)},
			Receipt: contracts.PublicRuntimeRoleReceipt{RoleName: "as_" + strings.ReplaceAll(p.InstallationID, "-", "") + fmt.Sprintf("_pub_%d", 70+i), RoleOID: 170 + uint32(i), LayoutDigest: p.LayoutDigest}})
	}
	return m
}

func TestCapacityCredentialManifestRetainsOriginalCompartmentAndIncarnation(t *testing.T) {
	for _, mode := range []string{"original-expired-claims", "namespace", "swapped", "hub-purpose", "extra", "missing", "duplicate-oid", "duplicate-claim", "root", "setup", "initial", "foreign-database", "foreign-process", "late-role", "expanded-claim", "unbounded-claim", "layout", "zero-input-digest", "future"} {
		t.Run(mode, func(t *testing.T) {
			m := capacityRuntimeManifestFixture()
			switch mode {
			case "namespace":
				m.Input.Namespace.Name = ""
			case "swapped":
				m.Roles[0], m.Roles[1] = m.Roles[1], m.Roles[0]
			case "hub-purpose":
				m.Roles[0].Purpose = "identity-read"
			case "extra":
				m.Roles = append(m.Roles, m.Roles[0])
			case "missing":
				m.Roles = m.Roles[:1]
			case "duplicate-oid":
				m.Roles[1].Receipt.RoleOID = m.Roles[0].Receipt.RoleOID
			case "duplicate-claim":
				m.Roles[1].Claim.OperationID = m.Roles[0].Claim.OperationID
			case "root":
				m.Capacity.RoleRootUID = m.SetupID
			case "setup":
				m.Capacity.RoleSetupID = m.RootUID
			case "initial":
				m.Capacity.InitialClaimID = m.RootUID
			case "foreign-database":
				m.Roles[0].Claim.DatabaseOID++
			case "foreign-process":
				m.Roles[0].Claim.PostmasterAt = m.Roles[0].Claim.PostmasterAt.Add(time.Second)
			case "late-role":
				m.Roles[0].Claim.ClaimedAt = m.Capacity.ClaimedAt.Add(time.Second)
				m.Roles[0].Claim.Until = m.Roles[0].Claim.ClaimedAt.Add(time.Second)
			case "expanded-claim":
				m.Capacity.Until = m.Capacity.ClaimedAt.Add(5*time.Second + time.Microsecond)
			case "unbounded-claim":
				m.Capacity.Until = time.Time{}
			case "layout":
				m.Roles[0].Receipt.LayoutDigest = strings.Repeat("c", 64)
			case "zero-input-digest":
				m.Capacity.InputDigest = strings.Repeat("0", 64)
			case "future":
				m.Capacity.ClaimedAt = time.Now().Add(time.Hour).Truncate(time.Microsecond)
				m.Capacity.Until = m.Capacity.ClaimedAt.Add(time.Second)
			}
			err := ValidateCapacityCredentialManifest(m, time.Now())
			if (mode == "original-expired-claims") != (err == nil) {
				t.Fatal("manifest boundary", err)
			}
			// A static historical manifest is never an active SQL verifier.
			if err = VerifyCapacityRuntimeCredential(context.Background(), nil, m, "capacity", app.CapacityQualification{}); err == nil {
				t.Fatal("no SQL login was accepted")
			}
		})
	}
}

func TestCapacityManifestClosedDecoderRejectsUnknownAndDuplicateFields(t *testing.T) {
	b, err := json.Marshal(capacityRuntimeManifestFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"unexpected":true,` + string(b[1:]), `{"format":"duplicate",` + string(b[1:]), string(b) + string(b)} {
		if _, err := contracts.DecodeCapacityCredentialManifest(strings.NewReader(raw)); err == nil {
			t.Fatal("noncanonical closed input accepted")
		}
	}
}
