package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func workerProjectionStateFixture(t *testing.T) (*InitialRuntimeResources, contracts.InitialRuntimeResourceState, time.Time) {
	t.Helper()
	s, state := installedWorkerResourceFixture(t)
	now := s.now().UTC().Truncate(time.Microsecond)
	setupAt, claimed := now.Add(-4*time.Second), now.Add(-2*time.Second)
	setup := contracts.CapacityRootSetupReceipt{Format: contracts.CapacityRootSetupFormat, OperationID: ownerID(2900), InstallationID: s.initial.InstallationID, InitialClaimID: ownerID(2901), PermissionRootID: ownerID(2902), RoleRootUID: ownerID(2903), RoleSetupID: ownerID(2904), InputDigest: strings.Repeat("a", 64), DatabaseOID: 42, PostmasterAt: now.Add(-time.Hour), ClaimedAt: setupAt, Until: setupAt.Add(5 * time.Second)}
	state.CleanupProjection = &contracts.CaptureCleanupProjectionClaim{OperationID: ownerID(2910), PublicDigest: strings.Repeat("b", 64), Setup: setup, ClaimedAt: claimed, Until: claimed.Add(5 * time.Second), Receipt: &contracts.CaptureCleanupProjectionReceipt{Secret: contracts.WorkerObjectReference{Name: contracts.HubWorkerCleanupProjectionName(s.initial.InstallationID), UID: ownerID(2911)}, ResourceVersion: "3", ObservedAt: now.Add(-time.Second)}}
	state.CapacityProjection = &contracts.CapacityRuntimeProjectionClaim{OperationID: ownerID(2912), PublicDigest: strings.Repeat("c", 64), Setup: setup, ClaimedAt: claimed, Until: claimed.Add(5 * time.Second), Receipt: &contracts.CapacityRuntimeProjectionReceipt{Secret: contracts.WorkerObjectReference{Name: contracts.CapacityRuntimeProjectionName(s.initial.InstallationID), UID: ownerID(2913)}, ResourceVersion: "4", ObservedAt: now.Add(-time.Second)}}
	return s, state, now
}

func TestWorkerProjectionRetainsHistoricalReceiptAndOriginalPendingClaim(t *testing.T) {
	s, state, now := workerProjectionStateFixture(t)
	before, _ := json.Marshal(state)
	if !s.valid(state) || !workerProjectionStateValid(s.initial.InstallationID, state, state.Until.Add(time.Hour)) {
		t.Fatal("exact historical provenance lost on ordinary restart")
	}
	after, _ := json.Marshal(state)
	if string(before) != string(after) {
		t.Fatal("validation mutated the retained original claim or receipt")
	}
	// Pending/unknown remains representable after its original claim end. This
	// is lookup-only provenance, not permission to recreate or start a runtime.
	state.CleanupProjection.Receipt = nil
	state.CapacityProjection.Receipt = nil
	if !workerProjectionStateValid(s.initial.InstallationID, state, now.Add(time.Hour)) {
		t.Fatal("expired unknown claim was erased instead of retained")
	}
}

func TestWorkerProjectionStateRejectsCrossCompartmentSubstitution(t *testing.T) {
	for name, mutate := range map[string]func(*contracts.InitialRuntimeResourceState){
		"legacy layout":          func(s *contracts.InitialRuntimeResourceState) { s.WorkerLayout = "" },
		"unfinished original":    func(s *contracts.InitialRuntimeResourceState) { s.Objects[18].Receipt = nil },
		"reused setup operation": func(s *contracts.InitialRuntimeResourceState) { s.CleanupProjection.OperationID = s.SetupID },
		"reused object operation": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.OperationID = s.Objects[0].OperationID
		},
		"reused capacity operation": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.OperationID = s.CapacityProjection.OperationID
		},
		"reused SQL setup operation": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.OperationID = s.CleanupProjection.Setup.OperationID
		},
		"reused object UID": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.Receipt.Secret.UID = s.Objects[0].Receipt.UID
		},
		"reused capacity UID": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.Receipt.Secret.UID = s.CapacityProjection.Receipt.Secret.UID
		},
		"reused role root UID": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.Receipt.Secret.UID = s.CleanupProjection.Setup.RoleRootUID
		},
		"capacity secret name": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.Receipt.Secret.Name = s.CapacityProjection.Receipt.Secret.Name
		},
		"different accepted setup": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.Setup.InputDigest = strings.Repeat("d", 64)
		},
		"wrong installation": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.Setup.InstallationID = ownerID(2990)
		},
		"new setup lifetime": func(s *contracts.InitialRuntimeResourceState) { s.Until = s.Until.Add(time.Second) },
		"long claim": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.Until = s.CleanupProjection.ClaimedAt.Add(6 * time.Second)
		},
		"late claim":   func(s *contracts.InitialRuntimeResourceState) { s.CleanupProjection.Until = s.Until.Add(time.Second) },
		"late receipt": func(s *contracts.InitialRuntimeResourceState) { s.CleanupProjection.Receipt.ObservedAt = s.Until },
		"future receipt": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.Receipt.ObservedAt = s.Until.Add(-time.Second)
		},
		"missing setup incarnation": func(s *contracts.InitialRuntimeResourceState) { s.CleanupProjection.Setup.DatabaseOID = 0 },
		"zero public digest": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.PublicDigest = strings.Repeat("0", 64)
		},
		"fractional original time": func(s *contracts.InitialRuntimeResourceState) {
			s.CleanupProjection.ClaimedAt = s.CleanupProjection.ClaimedAt.Add(time.Nanosecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, state, _ := workerProjectionStateFixture(t)
			mutate(&state)
			if s.valid(state) {
				t.Fatal("invalid projection survived the actual resource journal decoder boundary")
			}
		})
	}
}
