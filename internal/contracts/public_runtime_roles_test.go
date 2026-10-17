package contracts

import (
	"slices"
	"testing"
)

func TestPublicRuntimeCleanupCompartmentCannotEnterHubProjection(t *testing.T) {
	all, hub := PublicRuntimeRolePurposes(), PublicRuntimeHubRolePurposes()
	if len(all) != 80 || len(hub) != 51 || PublicRuntimeRetainedWorkerProcesses != 2 || PublicRuntimeRetainedHubProcesses != 4 {
		t.Fatal("unreviewed compartment expansion")
	}
	seen := map[int]bool{}
	for _, purpose := range all {
		id, ok := PublicRuntimeRoleOrdinal(purpose)
		if !ok || seen[id] {
			t.Fatal("missing or reused permanent role identity", purpose)
		}
		seen[id] = true
		limit, ok := PublicRuntimeRoleConnectionLimit(purpose)
		if !ok || limit < 1 {
			t.Fatal("unbounded installed role", purpose)
		}
	}
	for n, purpose := range PublicRuntimeCaptureCleanupPurposes() {
		id, ok := PublicRuntimeRoleOrdinal(purpose)
		if !ok || id != 43+n || !slices.Contains(all, purpose) || slices.Contains(hub, purpose) {
			t.Fatal("cleanup compartment or permanent identity changed", purpose)
		}
		limit, ok := PublicRuntimeRoleConnectionLimit(purpose)
		if !ok || limit != 3 {
			t.Fatal("cleanup exceeds two retained processes plus verifier", purpose)
		}
	}
	for n, purpose := range []string{"capacity", "capacity-capture"} {
		id, ok := PublicRuntimeRoleOrdinal(purpose)
		limit, bounded := PublicRuntimeRoleConnectionLimit(purpose)
		if !ok || id != 70+n || !bounded || limit != 3 || !slices.Contains(all, purpose) || slices.Contains(hub, purpose) {
			t.Fatal("capacity compartment changed", purpose)
		}
	}
	// ADR-172 appended connector-owner-read at 56 after the maintenance roles.
	connector := []int{48, 49, 50, 51, 52, 56, 53, 54, 55}
	for n, purpose := range append(PublicRuntimeFederationPurposes(), PublicRuntimeConnectorMaintenancePurposes()...) {
		id, ok := PublicRuntimeRoleOrdinal(purpose)
		limit, bounded := PublicRuntimeRoleConnectionLimit(purpose)
		if !ok || id != connector[n] || !bounded || limit != 3 || !slices.Contains(all, purpose) || slices.Contains(hub, purpose) {
			t.Fatal("connector compartment changed", purpose)
		}
	}
	for _, purpose := range hub {
		limit, ok := PublicRuntimeRoleConnectionLimit(purpose)
		if !ok || limit != 5 {
			t.Fatal("hub envelope changed", purpose)
		}
	}
	if _, ok := PublicRuntimeRoleConnectionLimit("caller-selected"); ok {
		t.Fatal("unknown purpose acquired a connection envelope")
	}
	all[0] = "changed"
	if PublicRuntimeRolePurposes()[0] == "changed" || PublicRuntimeHubRolePurposes()[0] == "changed" {
		t.Fatal("caller mutated compiled inventory")
	}
}
