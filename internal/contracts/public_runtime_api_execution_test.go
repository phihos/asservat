package contracts

import (
	"slices"
	"testing"
)

func TestPublicAPIExecutionConsolidatesOnlySameProcessFacets(t *testing.T) {
	all, hub := PublicRuntimeRolePurposes(), PublicRuntimeHubRolePurposes()
	if len(all) != 79 || len(hub) != 44 || !slices.Contains(hub, "api-execution") {
		t.Fatalf("execution credentials not consolidated: all=%d hub=%d", len(all), len(hub))
	}
	if ordinal, ok := PublicRuntimeRoleOrdinal("api-execution"); !ok || ordinal != 94 {
		t.Fatal("execution credential reused an old identity")
	}
	if limit, ok := PublicRuntimeRolePoolLimit("api-execution"); !ok || limit != 3 {
		t.Fatal("execution pool lost former aggregate concurrency")
	}
	if limit, ok := PublicRuntimeRoleConnectionLimit("api-execution"); !ok || limit != 4*3+1 {
		t.Fatal("execution login lost retained-process/verifier envelope")
	}
	for _, retired := range []string{"api-execution-read", "api-execution-prepare", "api-execution-record"} {
		_, ordinal := PublicRuntimeRoleOrdinal(retired)
		_, bounded := PublicRuntimeRoleConnectionLimit(retired)
		_, pooled := PublicRuntimeRolePoolLimit(retired)
		if slices.Contains(all, retired) || slices.Contains(hub, retired) || ordinal || bounded || pooled {
			t.Fatal("retired execution credential remains selectable", retired)
		}
	}
	for _, purpose := range []string{"capture-admit", "capture-journal", "capture-ack", "download-plan", "worker-config-read"} {
		if !slices.Contains(hub, purpose) {
			t.Fatal("independent hub duty disappeared", purpose)
		}
		if limit, ok := PublicRuntimeRolePoolLimit(purpose); !ok || limit != 1 {
			t.Fatal("independent hub pool changed", purpose)
		}
	}
	for _, purpose := range []string{"capacity", "capacity-capture", "connector-source", "connector-journal", "connector-ack", "context-verify", "context-publish", "key-wrap", "key-acquisition", "context-cleanup"} {
		if !slices.Contains(all, purpose) || slices.Contains(hub, purpose) {
			t.Fatal("separate pinned identity or process changed", purpose)
		}
	}
	if SQLConnectionsPerHubReplica != 32 {
		t.Fatal("execution consolidation raised process connection ceiling")
	}
}
