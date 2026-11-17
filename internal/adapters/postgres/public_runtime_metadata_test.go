package postgres

import (
	"slices"
	"strings"
	"testing"
)

func TestPublicMetadataReadHasExactExistingReadPrivileges(t *testing.T) {
	got, ok := publicRuntimeDutyGrants("hub-metadata-read")
	if !ok {
		t.Fatal("missing consolidated metadata credential")
	}
	want := []publicRuntimeGrant{
		// Row lock for a consistent child snapshot, no mutable metadata columns.
		{"table", "recording_save_group", "id", "UPDATE"},
		{"schema", "public", "", "USAGE"},
		{"table", "fleet_current_trust", "installation_id", "UPDATE"},
		{"table", "permission_stream", "id", "UPDATE"},
		{"function", "capacity_expensive_admits(uuid)", "", "EXECUTE"},
		{"function", "capacity_managed_admission_until(uuid,uuid,text,timestamptz)", "", "EXECUTE"},
		// On-demand capture account enrollment (capacity_enroll, SECURITY DEFINER).
		{"function", "capacity_enroll(uuid,uuid,text,text,uuid,uuid,bytea)", "", "EXECUTE"},
	}
	// Union of the seven pre-consolidation read facets, without redundant
	// column SELECTs already covered by a full-table SELECT in that union.
	for _, table := range []string{
		"goose_db_version", "fleet_current_trust", "permission_stream", "permission_basis", "permission_assignment", "authority_audit",
		"retention_policy", "retention_decision",
		"context_storage_binding", "custody_allocation", "custody_pool",
		"context_capture", "context_catalog", "custody_attempt", "context_verification", "context_execution", "context_case_locator",
		"processing_root", "context_processing", "processing_rule",
		// ADR-245: read with the permission projection that joins them.
		"permission_review_source", "permission_review_assignment", "permission_review_decision",
		// ADR-255: bounded summary state/source cutoff, no custody-copy writes.
		"capture_history_parameter", "recording_save_group",
		// ADR-335 D4: workload references match by name.
		"workload_name",
	} {
		want = append(want, publicRuntimeGrant{"table", table, "", "SELECT"})
	}
	slices.SortFunc(want, func(a, b publicRuntimeGrant) int { return strings.Compare(a.key(), b.key()) })
	if !slices.Equal(got, want) {
		t.Fatalf("metadata grant union changed:\n got %v\nwant %v", got, want)
	}
	for _, retired := range []string{"publisher-retention-read", "retention-source-audit", "retention-catchup", "permission-read", "retention-read", "storage-read", "progress-read", "case-read", "processing-read", "catalog-read"} {
		if _, ok := publicRuntimeRoleGrants(retired); ok {
			t.Fatal("retired standalone credential remains provisionable", retired)
		}
	}
}
