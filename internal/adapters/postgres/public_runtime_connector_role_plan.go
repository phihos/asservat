package postgres

// publicRuntimeConnectorGrants is the fixed SQL49/51 connector duty layout
// (ADR-170). Functions are the exact overloads the production adapters call
// for the selected connector-operation-history/v2 layout with prepaid
// retirement; the unreserved v1 admissions are deliberately absent. Lifecycle
// duties read the four filtered views and lock by their immutable keys only.
func publicRuntimeConnectorGrants(purpose string) ([]publicRuntimeGrant, bool) {
	out := []publicRuntimeGrant{{"schema", "public", "", "USAGE"}, {"table", "goose_db_version", "", "SELECT"}}
	functions := func(signatures ...string) {
		for _, s := range signatures {
			out = append(out, publicRuntimeGrant{"function", s, "", "EXECUTE"})
		}
	}
	lifecycle := func(columns ...string) {
		functions("connector_identity_role_ok(uuid,text)")
		for _, table := range []string{"connector_operation_pool", "connector_operation_account", "connector_operation_audit", "connector_operation_lifecycle", "fleet_current_trust"} {
			out = append(out, publicRuntimeGrant{"table", table, "", "SELECT"})
		}
		for _, column := range []string{"installation_id", "activated_postmaster_at", "activated_database_oid"} {
			out = append(out, publicRuntimeGrant{"table", "fleet_trust", column, "SELECT"})
		}
		for _, key := range []struct{ table, column string }{{"fleet_current_trust", "installation_id"}, {"connector_operation_pool", "root_id"}, {"connector_operation_account", "root_id"}, {"connector_operation_audit", "id"}, {"connector_operation_lifecycle", "operation_id"}} {
			out = append(out, publicRuntimeGrant{"table", key.table, key.column, "UPDATE"})
		}
		for _, column := range columns {
			out = append(out, publicRuntimeGrant{"table", "connector_operation_lifecycle", column, "UPDATE"})
		}
	}
	// ADR-193: the bootstrap claim and its acknowledgement lock the current
	// trust row and one fleet_bootstrap slot, as the enrollment adapters do.
	claim := func(columns ...string) {
		out = append(out, publicRuntimeGrant{"table", "fleet_current_trust", "", "SELECT"}, publicRuntimeGrant{"table", "fleet_current_trust", "installation_id", "UPDATE"}, publicRuntimeGrant{"table", "fleet_bootstrap", "", "SELECT"})
		for _, column := range columns {
			out = append(out, publicRuntimeGrant{"table", "fleet_bootstrap", column, "UPDATE"})
		}
	}
	switch purpose {
	case "connector-source":
		functions("stage_connector_identity(uuid,jsonb,jsonb)", "fence_connector_identity(uuid,uuid,timestamptz)", "promote_connector_backing(uuid,uuid,jsonb)")
	case "connector-journal":
		functions(
			"read_connector_process_admission(uuid,uuid,jsonb)", "read_connector_process_backing(uuid,jsonb)", "read_connector_process_ticket(uuid,jsonb)", "admit_connector_process_reserved(uuid,jsonb,jsonb,jsonb,bytea[])", "store_connector_process_outcome(uuid,uuid,jsonb,jsonb)", "accept_connector_process(uuid,uuid,jsonb)",
			"read_connector_credential_process(uuid,jsonb)", "read_connector_credential_attempt(uuid,uuid,jsonb)", "admit_connector_credential(uuid,jsonb,jsonb,jsonb)", "claim_connector_credential(uuid,uuid,jsonb,jsonb)", "store_connector_credential(uuid,uuid,jsonb,jsonb,jsonb)", "activate_connector_credential(uuid,uuid,jsonb,jsonb)",
			"connector_audit_journal(uuid,jsonb,text,jsonb)",
			"read_connector_backing_candidate(uuid,jsonb)", "read_connector_backing_admission(uuid,uuid,jsonb)", "read_connector_successor_cohorts(uuid,jsonb)", "admit_connector_backing_reserved(uuid,jsonb,jsonb,bytea[])", "store_connector_backing_outcome(uuid,uuid,jsonb,jsonb)",
			"read_connector_retirement(uuid,uuid,timestamptz,timestamptz)", "restrict_connector_retirement(uuid,uuid,text,jsonb)", "admit_connector_retirement(uuid,uuid,jsonb,timestamptz,timestamptz)", "store_connector_retirement_outcome(uuid,uuid,jsonb,timestamptz,timestamptz)",
		)
	case "connector-ack":
		functions("connector_audit_acknowledge(uuid,jsonb,text,jsonb,jsonb)")
		claim("id", "claim_acknowledged_at", "claim_audit_digest", "claim_object_key", "claim_object_version", "claim_object_etag", "claim_object_bytes", "claim_object_sha256")
	case "connector-read":
		// The activated-leaf registry plus the recovery state the duties read.
		functions("read_connector_activated_leaf(uuid,uuid,text,bytea,jsonb)")
		out = append(out, publicRuntimeGrant{"table", "fleet_current_trust", "", "SELECT"})
		// ADR-193: the federation resolves a presented peer from its staged
		// profile and the root backing (ConnectorIdentityProfiles).
		for _, column := range []string{"root_id", "peer_id", "installation_id", "cluster_id", "configuration", "suspended", "blocked"} {
			out = append(out, publicRuntimeGrant{"table", "connector_identity_profile", column, "SELECT"})
		}
		for _, column := range []string{"root_id", "backing"} {
			out = append(out, publicRuntimeGrant{"table", "connector_identity_root", column, "SELECT"})
		}
	case "cluster-credential":
		for _, column := range []string{"root_id", "peer_id", "installation_id", "cluster_id"} {
			out = append(out, publicRuntimeGrant{"table", "connector_identity_profile", column, "SELECT"})
		}
		// ADR-193: a lineage arises only through the bootstrap functions, so
		// this login inserts credentials (rotation) but never a lineage.
		for _, table := range []string{"cluster_enrollment_lineage", "cluster_enrollment_credential"} {
			for _, privilege := range []string{"SELECT", "UPDATE"} {
				out = append(out, publicRuntimeGrant{"table", table, "", privilege})
			}
		}
		out = append(out, publicRuntimeGrant{"table", "cluster_enrollment_credential", "", "INSERT"})
		claim("claimed_at", "public_key_sha256")
		functions("reserve_cluster_bootstrap(uuid,uuid,uuid,bytea,uuid,bigint,bytea,bigint,bigint)", "acknowledge_cluster_bootstrap(uuid,uuid,text,text,text,bigint,bytea)", "activate_cluster_bootstrap(uuid,uuid,bytea,bytea)")
	case "connector-owner-read":
		// ADR-172: the hub-api owner registry reads, for owner discovery and
		// authentication on behalf of regions. No owner write is granted.
		return ownerIdentityDutyGrants("registry")
	case "connector-cleanup":
		functions("detach_connector_identity(uuid,uuid)", "close_connector_retirement_admission(uuid,uuid)", "close_connector_retirement_writer_reference(uuid,uuid)", "delete_connector_retirement_ticket(uuid,uuid)")
		lifecycle("lease", "lease_fence", "retirement", "certificate_started", "certificate_completion", "terminal_purge", "overdue_selected_at", "overdue_purge")
	case "connector-verifier":
		lifecycle("certificate_verify_attempts", "certificate_receipt", "certificate_acknowledged_at", "terminal_acknowledged_at")
	case "connector-finalizer":
		functions("finish_connector_operation_retirement(uuid,uuid,uuid)", "finish_connector_operation_history(uuid,text,bytea,timestamptz,timestamptz,uuid)")
		lifecycle()
		out = append(out, publicRuntimeGrant{"table", "connector_operation_history", "", "SELECT"})
	default:
		return nil, false
	}
	return out, true
}
