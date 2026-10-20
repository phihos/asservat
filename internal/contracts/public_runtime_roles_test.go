package contracts

import (
	"slices"
	"testing"
)

func TestPublicRuntimeCleanupCompartmentCannotEnterHubProjection(t *testing.T) {
	all, hub := PublicRuntimeRolePurposes(), PublicRuntimeHubRolePurposes()
	// ADR-204 added three logins outside the hub projection (80 to 83),
	// ADR-205 three more (86) and ADR-210 one hub login (87, 52 in the hub).
	if len(all) != 87 || len(hub) != 52 || PublicRuntimeRetainedWorkerProcesses != 2 || PublicRuntimeRetainedHubProcesses != 4 {
		t.Fatal("unreviewed compartment expansion")
	}
	// ADR-205 decision 2: the hub-worker's deletion logins, in this order.
	if !slices.Equal(PublicRuntimeContextDeletionPurposes(), []string{"context-cleanup", "context-cleanup-audit", "context-cleanup-finalize"}) {
		t.Fatal("context deletion logins changed")
	}
	for n, purpose := range PublicRuntimeContextDeletionPurposes() {
		id, ok := PublicRuntimeRoleOrdinal(purpose)
		limit, bounded := PublicRuntimeRoleConnectionLimit(purpose)
		if !ok || id != 89+n || !bounded || limit != 3 || !slices.Contains(all, purpose) || slices.Contains(hub, purpose) {
			t.Fatal("context deletion compartment changed", purpose)
		}
	}
	for purpose, want := range map[string]int{"worker-config-observe": 86, "worker-config-audit": 87, "key-acquisition": 88} {
		id, ok := PublicRuntimeRoleOrdinal(purpose)
		limit, bounded := PublicRuntimeRoleConnectionLimit(purpose)
		if !ok || id != want || !bounded || limit != 3 || !slices.Contains(all, purpose) || slices.Contains(hub, purpose) {
			t.Fatal("download compartment changed", purpose)
		}
	}
	if !slices.Equal(PermissionProjectionPurposes(false, true, false), []string{"permission-accept", "permission-audit", "worker-config-observe", "worker-config-audit"}) || slices.Contains(PermissionProjectionPurposes(true, false, false), "worker-config-observe") || !slices.Contains(PublicRuntimeKeyServicePurposes(), "key-acquisition") {
		t.Fatal("download logins left their projections")
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
