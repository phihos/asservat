package kubernetes

import (
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func permissionProjectionStateFixture() (string, contracts.InitialRuntimeResourceState, time.Time) {
	installation, s, now := capacityProjectionStateFixture()
	s.CapacityProjection = nil
	claimed := s.CreatedAt.Add(20 * time.Second)
	s.PermissionProjection = &contracts.PermissionRuntimeProjectionClaim{OperationID: ownerID(1980), RootID: ownerID(1981), PublicDigest: strings.Repeat("4", 64), ClaimedAt: claimed, Until: claimed.Add(5 * time.Second),
		Receipt: &contracts.PermissionRuntimeProjectionReceipt{Secret: contracts.WorkerObjectReference{Name: contracts.PermissionRuntimeProjectionName(installation), UID: ownerID(1982)}, ResourceVersion: "3", ObservedAt: claimed.Add(time.Second)}}
	return installation, s, now
}

// ADR-189: the permission claim keeps the capacity claim's provenance shape.
func TestPermissionProjectionOriginalReceiptBoundary(t *testing.T) {
	for _, mode := range []string{"exact", "historical-complete", "reused-operation", "object-uid-reused", "wrong-secret-name", "long-claim", "fractional-time", "missing-root", "zero-digest", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			installation, s, now := permissionProjectionStateFixture()
			p := s.PermissionProjection
			switch mode {
			case "historical-complete":
				now = s.Until.Add(time.Hour)
			case "reused-operation":
				p.OperationID = s.Objects[0].OperationID
			case "object-uid-reused":
				p.Receipt.Secret.UID = s.Objects[0].Receipt.UID
			case "wrong-secret-name":
				p.Receipt.Secret.Name = contracts.CapacityRuntimeProjectionName(installation)
			case "long-claim":
				p.Until = p.ClaimedAt.Add(5*time.Second + time.Microsecond)
			case "fractional-time":
				p.ClaimedAt = p.ClaimedAt.Add(time.Nanosecond)
			case "missing-root":
				p.RootID = ""
			case "zero-digest":
				p.PublicDigest = strings.Repeat("0", 64)
			case "legacy":
				s.WorkerLayout = ""
			}
			if permissionProjectionStateValid(installation, s, now) != (mode == "exact" || mode == "historical-complete") {
				t.Fatal("permission claim boundary differs", mode)
			}
		})
	}
}

// Only the permission compartment may change, once to claim and once to its
// receipt, and never its identity, root or digest.
func TestPermissionProjectionTransitionIsOneWay(t *testing.T) {
	for _, mode := range []string{"claim", "complete", "claim-with-receipt", "same-pending", "change-root", "change-binding", "delete-claim"} {
		t.Run(mode, func(t *testing.T) {
			_, next, _ := permissionProjectionStateFixture()
			old := next
			pending := *next.PermissionProjection
			pending.Receipt = nil
			old.PermissionProjection = &pending
			switch mode {
			case "claim":
				old.PermissionProjection = nil
				claim := pending
				next.PermissionProjection = &claim
			case "claim-with-receipt":
				old.PermissionProjection = nil
			case "same-pending":
				claim := pending
				next.PermissionProjection = &claim
			case "change-root":
				claim := *next.PermissionProjection
				claim.RootID = ownerID(1999)
				next.PermissionProjection = &claim
			case "change-binding":
				next.BindingDigest = "changed"
			case "delete-claim":
				next.PermissionProjection = nil
			}
			if permissionProjectionTransition(old, next) != (mode == "claim" || mode == "complete") {
				t.Fatal("permission-only CAS boundary differs", mode)
			}
		})
	}
}
