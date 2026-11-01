package postgres

import (
	"slices"
	"strings"
	"testing"
)

// This literal retains the three original execution logins plus schema-102
// original policy reservation/grant reads and a grant row lock. An unrelated
// privilege, table-wide write or lost column fails.
func TestPublicAPIExecutionHasExactFormerGrantUnion(t *testing.T) {
	got, ok := publicRuntimeDutyGrants("api-execution")
	if !ok {
		t.Fatal("missing consolidated execution credential")
	}
	want := []publicRuntimeGrant{
		// ADR-266: parent membership/status and immutable cancellation intent only.
		{"table", "recording_save_group", "", "SELECT"},
		{"table", "recording_save_group", "progress_revision", "UPDATE"},
		{"table", "recording_save_group", "cancel_requested_at", "UPDATE"},
		{"table", "recording_save_group", "cancel_request_key", "UPDATE"},
		{"table", "context_capture", "snapshot_cancel_key", "UPDATE"},
		{"table", "context_capture", "snapshot_cancel_actor", "UPDATE"},
		{"table", "context_capture", "snapshot_cancel_requested_at", "UPDATE"},
		{"table", "context_capture", "snapshot_cancel_joined_at", "UPDATE"},
		{"table", "context_capture", "snapshot_cancel_proof", "UPDATE"},
		{"table", "context_capture", "snapshot_cancel_proof_digest", "UPDATE"},
		// SQL108: read the immutable manual save reservation; no insert/update.
		{"table", "recording_save_reservation", "", "SELECT"},
		{"table", "policy_recording_source", "", "SELECT"},
		{"table", "policy_recording_source", "root_id", "UPDATE"},
		{"table", "policy_occurrence", "", "SELECT"},
		{"table", "policy_acceptance", "", "SELECT"},
		{"table", "policy_source", "", "SELECT"},
		{"table", "access_grant", "", "SELECT"},
		{"table", "access_grant", "id", "UPDATE"},
		{"table", "access_grant", "policy_observed_bytes_spent", "UPDATE"},
		{"table", "policy_acceptance", "observed_bytes_spent", "UPDATE"},
		{"table", "policy_observation_session", "", "SELECT"},
		{"table", "policy_observation_session", "", "INSERT"},
		{"function", "lock_approved_context_grant(uuid,uuid,uuid,text,text,text,bytea)", "", "EXECUTE"},
		{"schema", "public", "", "USAGE"},
		{"table", "authority_audit", "", "SELECT"},
		{"table", "context_capture", "", "SELECT"},
		{"table", "context_capture", "id", "UPDATE"},
		{"table", "context_capture", "snapshot_coverage", "UPDATE"},
		{"table", "context_capture", "snapshot_coverage_digest", "UPDATE"},
		{"table", "context_capture", "snapshot_expectation_digest", "UPDATE"},
		{"table", "context_execution", "", "SELECT"},
		{"table", "context_execution", "acquired_at", "UPDATE"},
		{"table", "context_execution", "attempt_id", "INSERT"},
		{"table", "context_execution", "binding_json", "INSERT"},
		{"table", "context_execution", "capture_id", "INSERT"},
		{"table", "context_execution", "capture_id", "UPDATE"},
		{"table", "context_execution", "completed_at", "UPDATE"},
		{"table", "context_execution", "copies_digest", "UPDATE"},
		{"table", "context_execution", "copies_json", "UPDATE"},
		{"table", "context_execution", "expectation_digest", "INSERT"},
		{"table", "context_execution", "not_after", "INSERT"},
		{"table", "context_execution", "not_before", "INSERT"},
		{"table", "context_execution", "object_uid", "UPDATE"},
		{"table", "context_execution", "phase", "UPDATE"},
		{"table", "context_execution", "process_json", "INSERT"},
		{"table", "context_execution", "root_id", "INSERT"},
		{"table", "context_execution", "started_at", "UPDATE"},
		{"table", "context_execution", "writer_protocol", "INSERT"},
		{"table", "context_writer_completion", "", "INSERT"},
		{"table", "context_writer_completion", "", "SELECT"},
		{"table", "custody_allocation", "", "SELECT"},
		{"table", "custody_allocation", "id", "UPDATE"},
		{"table", "custody_attempt", "", "SELECT"},
		{"table", "custody_attempt", "id", "UPDATE"},
		{"table", "custody_pool", "", "SELECT"},
		{"table", "custody_pool", "id", "UPDATE"},
		{"table", "fleet_current_trust", "", "SELECT"},
		{"table", "fleet_current_trust", "installation_id", "UPDATE"},
		{"table", "fleet_trust", "activated_database_oid", "SELECT"},
		{"table", "fleet_trust", "activated_postmaster_at", "SELECT"},
		{"table", "fleet_trust", "installation_id", "SELECT"},
		{"table", "goose_db_version", "", "SELECT"},
		{"table", "permission_assignment", "", "SELECT"},
		{"table", "permission_basis", "", "SELECT"},
		{"table", "permission_review_assignment", "", "SELECT"},
		{"table", "permission_review_decision", "", "SELECT"},
		{"table", "permission_review_source", "", "SELECT"},
		{"table", "permission_stream", "", "SELECT"},
		{"table", "permission_stream", "id", "UPDATE"},
		{"table", "retention_catchup", "", "SELECT"},
		{"table", "retention_catchup_effect", "", "SELECT"},
		{"table", "retention_checkpoint", "", "SELECT"},
		{"table", "retention_decision", "", "SELECT"},
		{"table", "retention_source", "", "SELECT"},
		{"table", "retention_source", "root_id", "UPDATE"},
	}
	slices.SortFunc(want, func(a, b publicRuntimeGrant) int { return strings.Compare(a.key(), b.key()) })
	if !slices.Equal(got, want) {
		t.Fatalf("execution grant union changed:\n got %v\nwant %v", got, want)
	}
	for _, retired := range []string{"api-execution-read", "api-execution-prepare", "api-execution-record"} {
		if _, ok := publicRuntimeRoleGrants(retired); ok {
			t.Fatal("retired execution credential remains provisionable", retired)
		}
	}
	for _, grant := range got {
		if grant.privilege == "DELETE" || grant.kind == "function" && grant.object != "lock_approved_context_grant(uuid,uuid,uuid,text,text,text,bytea)" || grant.object == "custody_copy" || grant.object == "context_catalog" || strings.HasPrefix(grant.object, "download_") {
			t.Fatal("execution gained excluded deletion, publication, evidence-copy or download privilege", grant)
		}
	}
}
