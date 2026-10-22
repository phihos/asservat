package contracts

import (
	"slices"
	"testing"
)

func TestPublicMetadataReadConsolidatesOnlyHubReaders(t *testing.T) {
	all, hub := PublicRuntimeRolePurposes(), PublicRuntimeHubRolePurposes()
	if len(all) != 81 || len(hub) != 46 || !slices.Contains(hub, "hub-metadata-read") {
		t.Fatalf("metadata credentials were not consolidated: all=%d hub=%d", len(all), len(hub))
	}
	if ordinal, ok := PublicRuntimeRoleOrdinal("hub-metadata-read"); !ok || ordinal != 93 {
		t.Fatal("metadata credential reused an old identity")
	}
	if limit, ok := PublicRuntimeRoleConnectionLimit("hub-metadata-read"); !ok || limit != 4*7+1 {
		t.Fatal("metadata credential lost original aggregate concurrency and verifier bound")
	}
	for _, retired := range []string{"permission-read", "retention-read", "storage-read", "progress-read", "case-read", "processing-read", "catalog-read"} {
		_, ordinal := PublicRuntimeRoleOrdinal(retired)
		_, bounded := PublicRuntimeRoleConnectionLimit(retired)
		if slices.Contains(all, retired) || slices.Contains(hub, retired) || ordinal || bounded {
			t.Fatal("removed reader remains a selectable credential", retired)
		}
	}
	// These are different effects, processes or nested transactions. Combining
	// metadata must neither alias their identity nor move them into the hub.
	for _, retained := range []string{"download-plan", "worker-config-read", "download-source", "capture-intent-read", "capacity-profile-read", "capture-admit"} {
		if !slices.Contains(hub, retained) {
			t.Fatal("nonmetadata hub credential disappeared", retained)
		}
		if limit, ok := PublicRuntimeRoleConnectionLimit(retained); !ok || limit != 5 {
			t.Fatal("nonmetadata connection envelope changed", retained)
		}
	}
	for _, retained := range []string{"publisher-retention-read", "permission-accept", "context-cleanup", "key-acquisition"} {
		if !slices.Contains(all, retained) || slices.Contains(hub, retained) {
			t.Fatal("separate compartment changed", retained)
		}
	}
	if SQLConnectionsPerHubReplica != 32 {
		t.Fatal("consolidation increased the process connection budget")
	}
}
