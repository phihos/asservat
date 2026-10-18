package postgres

import (
	"slices"
	"testing"
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
			got, ok := publicRuntimeRoleGrants(purpose)
			if !ok || !slices.Equal(keys(got), keys(want)) {
				t.Fatalf("purpose grants differ: got %v, want %v", keys(got), keys(want))
			}
			for _, g := range got {
				// No purpose deletes, executes a function or updates a whole row,
				// and only the observer inserts.
				if g.privilege == "DELETE" || g.kind == "function" || g.privilege == "UPDATE" && g.column == "" || g.privilege == "INSERT" && purpose != "worker-config-observe" {
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
		got, _ := publicRuntimeRoleGrants(purpose)
		if slices.ContainsFunc(got, func(g publicRuntimeGrant) bool { return g.column == "used_roles" && g.privilege == "UPDATE" }) {
			t.Fatal("binding or verifier role can spend download key slots", purpose)
		}
	}
}
