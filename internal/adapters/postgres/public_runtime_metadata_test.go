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
		{"schema", "public", "", "USAGE"},
		{"table", "fleet_current_trust", "installation_id", "UPDATE"},
		{"table", "permission_stream", "id", "UPDATE"},
		{"table", "retention_source", "root_id", "UPDATE"},
		{"function", "capacity_managed_admission_until(uuid,uuid,text,timestamptz)", "", "EXECUTE"},
	}
	// Union of the seven pre-consolidation read facets, without redundant
	// column SELECTs already covered by a full-table SELECT in that union.
	for _, table := range []string{
		"goose_db_version", "fleet_current_trust", "permission_stream", "permission_basis", "permission_assignment", "authority_audit",
		"retention_source", "retention_checkpoint", "retention_catchup", "retention_catchup_effect", "retention_decision",
		"context_storage_binding", "custody_allocation", "custody_pool", "context_control_pool", "context_control_account",
		"context_capture", "context_catalog", "custody_attempt", "context_verification", "context_execution", "context_case_locator",
		"processing_root", "context_processing", "processing_rule",
		// ADR-245: read with the permission projection that joins them.
		"permission_review_source", "permission_review_assignment", "permission_review_decision",
	} {
		want = append(want, publicRuntimeGrant{"table", table, "", "SELECT"})
	}
	slices.SortFunc(want, func(a, b publicRuntimeGrant) int { return strings.Compare(a.key(), b.key()) })
	if !slices.Equal(got, want) {
		t.Fatalf("metadata grant union changed:\n got %v\nwant %v", got, want)
	}
	for _, retired := range []string{"permission-read", "retention-read", "storage-read", "progress-read", "case-read", "processing-read", "catalog-read"} {
		if _, ok := publicRuntimeRoleGrants(retired); ok {
			t.Fatal("retired standalone credential remains provisionable", retired)
		}
	}
}

func TestPublisherRetentionCredentialRemainsNarrow(t *testing.T) {
	grants, ok := publicRuntimeRoleGrants("publisher-retention-read")
	if !ok {
		t.Fatal("publisher lost its independent retention credential")
	}
	for _, g := range grants {
		if g.kind == "schema" && g.object == "public" && g.privilege == "USAGE" {
			continue
		}
		if g.kind == "table" && g.privilege == "SELECT" && g.column == "" && slices.Contains([]string{"goose_db_version", "permission_stream", "retention_source", "retention_checkpoint", "retention_catchup", "retention_catchup_effect", "retention_decision"}, g.object) {
			continue
		}
		if g.kind == "table" && g.privilege == "UPDATE" && (g.object == "permission_stream" && g.column == "id" || g.object == "retention_source" && g.column == "root_id") {
			continue
		}
		t.Fatal("hub metadata privilege escaped into publisher", g)
	}
	if len(grants) != 10 {
		t.Fatal("publisher retention grant disappeared")
	}
}
