package contracts

import (
	"slices"
	"testing"
)

func TestPublicRuntimeCleanupCompartmentCannotEnterHubProjection(t *testing.T) {
	all, hub := PublicRuntimeRolePurposes(), PublicRuntimeHubRolePurposes()
	// Physical hub credentials are consolidated; separate process roles remain.
	if PublicRuntimeRetainedWorkerProcesses != 2 || PublicRuntimeRetainedHubProcesses != 4 {
		t.Fatalf("unexpected retained process counts: worker=%d hub=%d", PublicRuntimeRetainedWorkerProcesses, PublicRuntimeRetainedHubProcesses)
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
	if !slices.Equal(PermissionProjectionPurposes(false, true, false), []string{"permission-accept", "worker-config-observe", "worker-config-audit"}) || slices.Contains(PermissionProjectionPurposes(true, false, false), "worker-config-observe") || !slices.Contains(PublicRuntimeKeyServicePurposes(), "key-acquisition") {
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
		if !ok || (!slices.Contains(PublicRuntimeFederationPurposes(), purpose) && limit < 1) {
			t.Fatal("missing connection budget", purpose)
		}
	}
	for n, purpose := range []string{"capacity", "capacity-capture"} {
		id, ok := PublicRuntimeRoleOrdinal(purpose)
		limit, bounded := PublicRuntimeRoleConnectionLimit(purpose)
		if !ok || id != 70+n || !bounded || limit != 3 || !slices.Contains(all, purpose) || slices.Contains(hub, purpose) {
			t.Fatal("capacity compartment changed", purpose)
		}
	}
	connector := []int{52, 56}
	for n, purpose := range PublicRuntimeFederationPurposes() {
		id, ok := PublicRuntimeRoleOrdinal(purpose)
		limit, bounded := PublicRuntimeRoleConnectionLimit(purpose)
		if !ok || id != connector[n] || !bounded || limit != PublicRuntimeFederationRoleConnections || !slices.Contains(all, purpose) || slices.Contains(hub, purpose) {
			t.Fatal("connector compartment changed", purpose)
		}
	}
	for _, purpose := range hub {
		limit, ok := PublicRuntimeRoleConnectionLimit(purpose)
		want := 5
		if purpose == "hub-runtime" {
			want = 81
		}
		if !ok || limit != want {
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
