package kubernetes

import (
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func capacityProjectionStateFixture() (string, contracts.InitialRuntimeResourceState, time.Time) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	start := now.Add(-time.Minute)
	installation := ownerID(1900)
	s := contracts.InitialRuntimeResourceState{Format: contracts.InitialRuntimeResourcesFormat, SetupID: ownerID(1901), BindingDigest: strings.Repeat("1", 64), WorkerLayout: contracts.HubWorkerInstalledLayout, CreatedAt: start, Until: start.Add(30 * time.Minute)}
	for i, item := range initialRuntimeResourceItems {
		s.Objects = append(s.Objects, contracts.InitialRuntimeResourceClaim{Item: item, OperationID: ownerID(1910 + i), Receipt: &contracts.InitialRuntimeResourceReceipt{UID: ownerID(1940 + i), ResourceVersion: "1", Generation: 1}})
	}
	setup := start.Add(time.Second)
	claimed := start.Add(10 * time.Second)
	s.CapacityProjection = &contracts.CapacityRuntimeProjectionClaim{OperationID: ownerID(1970), PublicDigest: strings.Repeat("2", 64), ClaimedAt: claimed, Until: claimed.Add(5 * time.Second), Setup: contracts.CapacityRootSetupReceipt{Format: contracts.CapacityRootSetupFormat, OperationID: ownerID(1971), InstallationID: installation, InitialClaimID: ownerID(1972), PermissionRootID: ownerID(1973), RoleRootUID: ownerID(1974), RoleSetupID: ownerID(1975), InputDigest: strings.Repeat("3", 64), DatabaseOID: 42, PostmasterAt: start.Add(-time.Hour), ClaimedAt: setup, Until: setup.Add(5 * time.Second)}, Receipt: &contracts.CapacityRuntimeProjectionReceipt{Secret: contracts.WorkerObjectReference{Name: contracts.CapacityRuntimeProjectionName(installation), UID: ownerID(1976)}, ResourceVersion: "2", ObservedAt: claimed.Add(2 * time.Second)}}
	return installation, s, now
}

func TestCapacityProjectionOriginalReceiptBoundary(t *testing.T) {
	for _, mode := range []string{"exact", "historical-complete", "lookup-observed-after-create-interval", "legacy", "missing-object", "reused-operation", "wrong-secret-name", "wrong-installation", "moved-claim", "late-receipt", "before-setup", "fractional-time", "missing-sql-incarnation", "zero-public-digest", "zero-setup-digest", "setup-operation-reused", "role-root-used-as-projection"} {
		t.Run(mode, func(t *testing.T) {
			installation, s, now := capacityProjectionStateFixture()
			p := s.CapacityProjection
			switch mode {
			case "historical-complete":
				now = s.Until.Add(time.Hour)
			case "lookup-observed-after-create-interval":
				p.Receipt.ObservedAt = p.Until.Add(time.Second)
			case "legacy":
				s.WorkerLayout = ""
			case "missing-object":
				s.Objects[0].Receipt = nil
			case "reused-operation":
				p.OperationID = s.Objects[0].OperationID
			case "wrong-secret-name":
				p.Receipt.Secret.Name += "-other"
			case "wrong-installation":
				p.Setup.InstallationID = ownerID(1980)
			case "moved-claim":
				p.Until = s.Until.Add(time.Second)
			case "late-receipt":
				p.Receipt.ObservedAt = s.Until
				now = s.Until.Add(time.Second)
			case "before-setup":
				p.Setup.ClaimedAt = p.ClaimedAt.Add(time.Second)
			case "fractional-time":
				p.ClaimedAt = p.ClaimedAt.Add(time.Nanosecond)
			case "missing-sql-incarnation":
				p.Setup.DatabaseOID = 0
			case "zero-public-digest":
				p.PublicDigest = strings.Repeat("0", 64)
			case "zero-setup-digest":
				p.Setup.InputDigest = strings.Repeat("0", 64)
			case "setup-operation-reused":
				p.OperationID = p.Setup.OperationID
			case "role-root-used-as-projection":
				p.Receipt.Secret.UID = p.Setup.RoleRootUID
			}
			want := mode == "exact" || mode == "historical-complete" || mode == "lookup-observed-after-create-interval"
			if capacityProjectionStateValid(installation, s, now) != want {
				t.Fatal("original projection boundary differs", mode)
			}
		})
	}
}
