package postgres

import (
	"slices"
	"testing"
)

// The actual generated query INSERT names this column for both comparison and
// legacy NULL. Exercise the installed role union, not an administrator fixture.
func TestProfileComparisonWorkerInsertHasExactInstalledColumnGrant(t *testing.T) {
	want := publicRuntimeGrant{"table", "download_worker", "baseline_query_allocation_id", "INSERT"}
	for _, purpose := range []string{"download-worker", "hub-runtime"} {
		var grants []publicRuntimeGrant
		var ok bool
		if purpose == "download-worker" {
			grants, ok = publicRuntimeDutyGrants(purpose)
		} else {
			grants, ok = publicRuntimeRoleGrants(purpose)
		}
		if !ok || !slices.Contains(grants, want) {
			t.Fatalf("%s cannot issue the generated typed query-worker INSERT", purpose)
		}
		if slices.Contains(grants, publicRuntimeGrant{"table", "download_worker", "", "INSERT"}) {
			t.Fatal("query path broadened to whole-table worker insertion")
		}
	}
	keys, ok := publicRuntimeRoleGrants("key-acquisition")
	if !ok || slices.Contains(keys, want) {
		t.Fatal("key consumer gained worker insertion")
	}
}
