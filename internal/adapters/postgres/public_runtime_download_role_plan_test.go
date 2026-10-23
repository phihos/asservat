package postgres

import (
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// ADR-204 decisions 7 and 8: closed allow-lists, including lock columns,
// derived from the WorkerConfigurations and NativeKeyAuthority statements.
// A broader table grant or an extra privilege must fail.
func TestDownloadAcceptanceAndAcquisitionRolesHaveExactPurposeGrants(t *testing.T) {
	common := []publicRuntimeGrant{{"schema", "public", "", "USAGE"}, {"table", "goose_db_version", "", "SELECT"}}
	with := func(extra ...publicRuntimeGrant) []publicRuntimeGrant { return append(slices.Clone(common), extra...) }
	read := func(tables ...string) []publicRuntimeGrant {
		out := make([]publicRuntimeGrant, len(tables))
		for i, table := range tables {
			out[i] = publicRuntimeGrant{"table", table, "", "SELECT"}
		}
		return out
	}
	columns := func(table, privilege string, names ...string) []publicRuntimeGrant {
		out := make([]publicRuntimeGrant, len(names))
		for i, name := range names {
			out[i] = publicRuntimeGrant{"table", table, name, privilege}
		}
		return out
	}
	observe := with(read("fleet_current_trust", "download_worker_configuration", "download_worker_configuration_revision")...)
	observe = append(observe, publicRuntimeGrant{"table", "fleet_current_trust", "installation_id", "UPDATE"})
	observe = append(observe, columns("download_worker_configuration", "INSERT", "installation_id", "cluster_id", "source_uid", "generation", "observed_at", "fresh_until")...)
	observe = append(observe, columns("download_worker_configuration", "UPDATE", "generation", "observed_at", "fresh_until")...)
	observe = append(observe, columns("download_worker_configuration_revision", "INSERT", "installation_id", "cluster_id", "source_uid", "generation", "snapshot_json")...)
	acknowledge := with(read("download_worker_configuration", "download_worker_configuration_revision")...)
	acknowledge = append(acknowledge, publicRuntimeGrant{"table", "download_worker_configuration", "source_uid", "UPDATE"}, publicRuntimeGrant{"table", "download_worker_configuration_revision", "audit_receipt_json", "UPDATE"})
	acquisition := with(read("fleet_current_trust", "permission_stream", "authority_audit", "artifact_download", "download_batch",
		"processing_root", "context_processing", "processing_rule",
		"retention_source", "retention_checkpoint", "retention_catchup", "retention_catchup_effect", "retention_decision",
		"context_capture", "context_verification", "download_key_binding", "download_native_key", "download_native_owner",
		"download_response", "download_window", "download_worker", "download_worker_enrollment", "download_worker_certificate",
		"download_worker_configuration", "download_worker_configuration_revision")...)
	acquisition = append(acquisition, columns("context_catalog", "SELECT", "artifact_id", "root_id", "capture_id", "published_at")...)
	acquisition = append(acquisition, columns("custody_attempt", "SELECT", "id", "artifact_id", "state", "copies_digest", "effective_expires_at", "effective_delete_by")...)
	acquisition = append(acquisition, publicRuntimeGrant{"table", "fleet_current_trust", "installation_id", "UPDATE"})
	for _, table := range []string{"permission_stream", "artifact_download", "download_response", "download_window", "download_worker"} {
		acquisition = append(acquisition, publicRuntimeGrant{"table", table, "id", "UPDATE"})
	}
	acquisition = append(acquisition,
		publicRuntimeGrant{"table", "retention_source", "root_id", "UPDATE"},
		publicRuntimeGrant{"table", "download_worker_configuration", "source_uid", "UPDATE"},
		publicRuntimeGrant{"table", "download_native_owner", "worker_id", "UPDATE"},
		publicRuntimeGrant{"table", "download_key_binding", "used_roles", "UPDATE"},
		publicRuntimeGrant{"table", "download_native_key", "used_roles", "UPDATE"})
	// ADR-219 adds the same typed query SQL fences and only the existing
	// irreversible key-consumption write to the isolated acquisition key role.
	acquisition = append(acquisition, read("context_case_locator", "operation_audit", "operation_audit_lifecycle", "context_query_backing", "context_query_allocation", "context_query_principal", "context_query", "context_query_call", "context_query_worker", "context_query_batch", "context_query_key_binding")...)
	for _, table := range []string{"operation_audit", "context_query_allocation", "context_query_principal", "context_query", "context_query_batch"} {
		acquisition = append(acquisition, publicRuntimeGrant{"table", table, "id", "UPDATE"})
	}
	acquisition = append(acquisition, publicRuntimeGrant{"table", "operation_audit_lifecycle", "operation_id", "UPDATE"}, publicRuntimeGrant{"table", "context_query_backing", "root_id", "UPDATE"}, publicRuntimeGrant{"table", "context_query_key_binding", "used_roles", "UPDATE"})
	for _, signature := range []string{"lock_context_query_capacity(uuid,uuid)", "context_query_capacity_allocation_current(uuid,uuid)", "context_query_shared_profile_current(uuid,jsonb)"} {
		acquisition = append(acquisition, publicRuntimeGrant{"function", signature, "", "EXECUTE"})
	}
	keys := func(v []publicRuntimeGrant) []string {
		out := make([]string, len(v))
		for n, g := range v {
			out[n] = g.key()
		}
		slices.Sort(out)
		return out
	}
	for purpose, want := range map[string][]publicRuntimeGrant{"worker-config-observe": observe, "worker-config-audit": acknowledge, "key-acquisition": acquisition} {
		t.Run(purpose, func(t *testing.T) {
			got, ok := publicRuntimeDutyGrants(purpose)
			if !ok || !slices.Equal(keys(got), keys(want)) {
				t.Fatalf("purpose grants differ: got %v, want %v", keys(got), keys(want))
			}
			for _, g := range got {
				// No purpose deletes or updates a whole row; only the observer
				// inserts. The key role has the three exact query fences above.
				if g.privilege == "DELETE" || g.kind == "function" && purpose != "key-acquisition" || g.privilege == "UPDATE" && g.column == "" || g.privilege == "INSERT" && purpose != "worker-config-observe" {
					t.Fatal("effect beyond the purpose", g.key())
				}
			}
		})
	}
	// The observer cannot acknowledge its own revision, the acknowledgement
	// cannot stage or refresh one, and only acquisition spends key slots.
	if slices.Contains(observe, publicRuntimeGrant{"table", "download_worker_configuration_revision", "audit_receipt_json", "UPDATE"}) || slices.ContainsFunc(acknowledge, func(g publicRuntimeGrant) bool { return g.column == "fresh_until" || g.privilege == "INSERT" }) {
		t.Fatal("observer and audit acknowledgement merged")
	}
	for _, purpose := range []string{"download-key-bind", "native-key-bind", "key-verify"} {
		got, _ := publicRuntimeDutyGrants(purpose)
		if slices.ContainsFunc(got, func(g publicRuntimeGrant) bool { return g.column == "used_roles" && g.privilege == "UPDATE" }) {
			t.Fatal("binding or verifier role can spend download key slots", purpose)
		}
	}
}

// ADR-204: Downloads.downloadFence reads the current processing snapshot
// (readProcessingSnapshot) and checks the accepted retention sources
// (RetentionTransactionGuard.check). Every purpose whose adapter runs that
// fence needs exactly these reads; the audit, identity, stop and plan
// purposes run no fence and must not gain them.
func TestDownloadFencePurposesReadProcessingAndRetention(t *testing.T) {
	var fence []publicRuntimeGrant
	for _, table := range []string{"processing_root", "context_processing", "processing_rule", "retention_source", "retention_checkpoint", "retention_catchup", "retention_catchup_effect", "retention_decision"} {
		fence = append(fence, publicRuntimeGrant{"table", table, "", "SELECT"})
	}
	// Downloads (download-session, download-source), DownloadWorkers.withSession
	// (download-worker and through it
	// native-owner, native-key-bind), Downloads.withKeyBatch (download-key-bind)
	// and the browser refresh effects (refresh-admit, refresh-owner).
	for _, purpose := range []string{"download-session", "download-source", "download-worker", "worker-enrollment", "worker-enrollment-activate", "native-owner", "download-key-bind", "native-key-bind", "refresh-admit", "refresh-owner"} {
		got, ok := publicRuntimeDutyGrants(purpose)
		if !ok {
			t.Fatal("missing purpose", purpose)
		}
		for _, g := range fence {
			if !slices.Contains(got, g) {
				t.Errorf("%s runs the download fence without %s", purpose, g.key())
			}
		}
	}
	// download-worker-identity serves only readWorkerIdentity (no fence).
	for _, purpose := range []string{"download-audit", "download-worker-audit", "download-worker-identity", "worker-enrollment-audit", "download-stop", "download-stop-writer", "download-stop-ack", "download-plan", "worker-config-read"} {
		got, _ := publicRuntimeDutyGrants(purpose)
		for _, g := range fence {
			if slices.Contains(got, g) {
				t.Errorf("%s runs no download fence but reads %s", purpose, g.key())
			}
		}
	}
	// The additions are reads only: no hub extension purpose writes a
	// processing table or a retention table beyond the root_id lock column.
	// ADR-210's processing-decision is the one processing writer.
	for _, purpose := range contracts.PublicRuntimeHubSharedDuties() {
		if purpose == "processing-decision" {
			continue
		}
		got, _ := publicRuntimeDutyGrants(purpose)
		for _, g := range got {
			lock := g.object == "retention_source" && g.column == "root_id" && g.privilege == "UPDATE"
			if g.privilege != "SELECT" && !lock && (strings.Contains(g.object, "processing") || strings.HasPrefix(g.object, "retention_")) {
				t.Errorf("%s gained %s", purpose, g.key())
			}
		}
	}
}
