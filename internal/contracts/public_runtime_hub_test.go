package contracts

import (
	"slices"
	"testing"
)

func TestHubCredentialsPreserveProcessAndPinnedBoundaries(t *testing.T) {
	all, hub := PublicRuntimeRolePurposes(), PublicRuntimeHubRolePurposes()
	want := []string{"hub-runtime", "capture-intent-read", "worker-config-read", "capacity-profile-read", "capture-admit", "capture-journal", "capture-ack"}
	if len(all) != 43 || !slices.Equal(hub, want) {
		t.Fatalf("wrong physical inventory: all=%d hub=%v", len(all), hub)
	}
	if n, ok := PublicRuntimeRoleOrdinal("hub-runtime"); !ok || n != 95 {
		t.Fatal("shared credential reused a retired identity")
	}
	if n, ok := PublicRuntimeRoleConnectionLimit("hub-runtime"); !ok || n != 81 {
		t.Fatal("shared role lost its aggregate retained-process bound")
	}
	for _, duty := range append(PublicRuntimeHubSharedDuties(), "browser-cleanup", "worker-owner", "permission-read", "retention-read", "storage-read", "progress-read", "case-read", "processing-read", "catalog-read", "api-execution-read", "api-execution-prepare", "api-execution-record") {
		_, ordinal := PublicRuntimeRoleOrdinal(duty)
		_, bounded := PublicRuntimeRoleConnectionLimit(duty)
		if slices.Contains(all, duty) || ordinal || bounded {
			t.Fatal("retired duty still creates a credential", duty)
		}
	}
	for _, purpose := range []string{"browser-settings", "capacity", "capacity-capture", "connector-source", "context-verify", "context-publish", "key-wrap", "key-acquisition", "context-cleanup"} {
		if !slices.Contains(all, purpose) || slices.Contains(hub, purpose) {
			t.Fatal("separate process credential moved into hub", purpose)
		}
	}
	for _, purpose := range want[1:] {
		if n, ok := PublicRuntimeRolePoolLimit(purpose); !ok || n != 1 {
			t.Fatal("pinned or nested pool changed", purpose)
		}
	}
	if !slices.Equal(OwnerIdentityRolePurposes(), []string{"owner-runtime"}) || OwnerIdentityPoolConnections != 6 || OwnerIdentityRoleConnections != 25 || SQLConnectionsPerHubReplica != 32 {
		t.Fatal("owner or process connection envelope changed")
	}
	for _, retired := range []string{"enrollment", "audit", "activation", "registry", "routing", "native-read"} {
		if _, ok := OwnerIdentityRoleOrdinal(retired); ok {
			t.Fatal("retired owner credential retained", retired)
		}
	}
	if n, ok := OwnerIdentityRoleOrdinal("owner-runtime"); !ok || n != 6 {
		t.Fatal("owner identity was reused")
	}
}

func TestHubBudgetCountsConnectionsRatherThanPasswords(t *testing.T) {
	plan, err := InstalledSQLConnectionPlan(1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := plan.Validate(0, SQLServerCapacity{MaxConnections: 1000})
	if err != nil || got.PerHubProcess != 32 {
		t.Fatal("physical budget rejected consolidated credentials", got, err)
	}
	for i, c := range plan.Compartments {
		if !c.Hub {
			continue
		}
		if len(c.Purposes) != 8 || c.PoolCapacity != 32 {
			t.Fatal("hub budget still counts old credentials", c)
		}
		plan.Compartments[i].PoolCapacity = 31
		if _, err = plan.Validate(0, SQLServerCapacity{MaxConnections: 1000}); err == nil {
			t.Fatal("governor exceeds compiled pool capacity")
		}
	}
}
