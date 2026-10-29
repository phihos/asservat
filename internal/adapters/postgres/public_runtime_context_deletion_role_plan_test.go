package postgres

import (
	"slices"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// ADR-205 decision 2: closed allow-lists, including lock columns, equal to the
// ADR-111 fixture roles context_cleanup_runtime, context_cleanup_audit_runtime
// and context_cleanup_finalize_runtime in test/fixtures/sql/runtime-roles.sql;
// the cleaner additionally holds context_deadline_runtime's grants (ADR-223).
// A broader table grant or an extra privilege must fail.
func TestContextDeletionRolesHaveExactFixtureGrants(t *testing.T) {
	table := func(name, privilege string, columns ...string) []publicRuntimeGrant {
		if len(columns) == 0 {
			return []publicRuntimeGrant{{"table", name, "", privilege}}
		}
		out := make([]publicRuntimeGrant, len(columns))
		for i, column := range columns {
			out[i] = publicRuntimeGrant{"table", name, column, privilege}
		}
		return out
	}
	join := func(parts ...[]publicRuntimeGrant) []publicRuntimeGrant { return slices.Concat(parts...) }
	common := join([]publicRuntimeGrant{{"schema", "public", "", "USAGE"}},
		table("goose_db_version", "SELECT"), table("permission_stream", "SELECT"), table("fleet_current_trust", "SELECT"),
		table("context_execution", "SELECT"), table("context_writer_completion", "SELECT"), table("context_deletion_checkpoint", "SELECT"),
		table("fleet_trust", "SELECT", "installation_id", "activated_postmaster_at", "activated_database_oid"),
		table("fleet_current_trust", "UPDATE", "installation_id"), table("permission_stream", "UPDATE", "id"))
	custody := join(table("custody_pool", "SELECT"), table("custody_allocation", "SELECT"), table("custody_attempt", "SELECT"), table("custody_copy", "SELECT"),
		table("custody_pool", "UPDATE", "id"), table("custody_allocation", "UPDATE", "id"), table("custody_attempt", "UPDATE", "id"))
	cleanup := join(common, custody,
		table("custody_attempt", "UPDATE", "state", "deletion_fence", "lease_until"),
		table("context_deletion_checkpoint", "INSERT"),
		// ADR-223: the fixture context_deadline_runtime grants.
		table("context_capture", "SELECT"), table("context_catalog", "SELECT"),
		table("context_capture", "UPDATE", "deadline_observed_at"))
	acknowledge := join(common,
		table("context_deletion_checkpoint", "UPDATE", "attempt_id", "audit_receipt_json", "audit_acknowledged_at"))
	finalize := join(common, custody,
		table("policy_observation_session", "SELECT", "root_id", "capture_id"), table("policy_observation_session", "DELETE"),
		table("context_deletion_checkpoint", "UPDATE", "attempt_id", "finalization_xid"),
		table("custody_allocation", "UPDATE", "charged_bytes", "charged_objects"),
		table("custody_attempt", "UPDATE", "state", "deleted_at", "lease_until"),
		table("custody_copy", "UPDATE", "ciphertext_bytes", "ciphertext_sha256", "etag", "version_id"),
		table("custody_event", "INSERT"))
	keys := func(v []publicRuntimeGrant) []string {
		out := make([]string, len(v))
		for n, g := range v {
			out[n] = g.key()
		}
		slices.Sort(out)
		return out
	}
	want := map[string][]publicRuntimeGrant{"context-cleanup": cleanup, "context-cleanup-audit": acknowledge, "context-cleanup-finalize": finalize}
	for _, purpose := range contracts.PublicRuntimeContextDeletionPurposes() {
		t.Run(purpose, func(t *testing.T) {
			got, ok := publicRuntimeRoleGrants(purpose)
			if !ok || !slices.Equal(keys(got), keys(want[purpose])) {
				t.Fatalf("purpose grants differ: got %v, want %v", keys(got), keys(want[purpose]))
			}
			for _, g := range got {
				// Only the finalizer deletes the protected finite observation child.
				if g.kind == "function" || g.privilege == "DELETE" && (purpose != "context-cleanup-finalize" || g.object != "policy_observation_session") {
					t.Fatal("effect beyond the purpose", g.key())
				}
			}
		})
	}
	// The cleaner cannot acknowledge or finalize its own purge, the audit
	// login cannot purge or release, and only the finalizer releases charges.
	has := func(purpose string, g publicRuntimeGrant) bool {
		got, _ := publicRuntimeRoleGrants(purpose)
		return slices.Contains(got, g)
	}
	receipt := publicRuntimeGrant{"table", "context_deletion_checkpoint", "audit_receipt_json", "UPDATE"}
	claim := publicRuntimeGrant{"table", "context_deletion_checkpoint", "finalization_xid", "UPDATE"}
	release := publicRuntimeGrant{"table", "custody_allocation", "charged_bytes", "UPDATE"}
	record := publicRuntimeGrant{"table", "context_deletion_checkpoint", "", "INSERT"}
	if has("context-cleanup", receipt) || has("context-cleanup", claim) || has("context-cleanup", release) ||
		has("context-cleanup-audit", record) || has("context-cleanup-audit", claim) || has("context-cleanup-audit", release) ||
		has("context-cleanup-finalize", record) || has("context-cleanup-finalize", receipt) {
		t.Fatal("cleanup, audit acknowledgement and finalization merged")
	}
	// The due list needs only the cleaner's reads.
	for _, g := range []publicRuntimeGrant{{"table", "custody_attempt", "", "SELECT"}, {"table", "context_writer_completion", "", "SELECT"}} {
		if !has("context-cleanup", g) {
			t.Fatal("cleaner cannot list due deletions", g.key())
		}
	}
}
