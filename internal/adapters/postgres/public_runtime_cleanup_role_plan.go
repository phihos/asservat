package postgres

// The three A-HWORK capture lifecycle credentials use private filtered views.
// This list is derived from captureLifecycleQueries and its recovery-first
// transaction, not broad grants on the human audit tables. It does not make a
// purpose creatable before the separate protected worker projection is bound.
func publicRuntimeCaptureCleanupGrants(purpose string) ([]publicRuntimeGrant, bool) {
	if purpose != "capture-cleanup" && purpose != "capture-verifier" && purpose != "capture-finalizer" {
		return nil, false
	}
	out := []publicRuntimeGrant{{"schema", "public", "", "USAGE"}, {"table", "goose_db_version", "", "SELECT"}, {"function", "capture_audit_role_ok(uuid,text)", "", "EXECUTE"}}
	for _, table := range []string{"capture_operation_pool", "capture_operation_account", "capture_operation_audit", "capture_operation_lifecycle", "capture_operation_history", "fleet_current_trust"} {
		out = append(out, publicRuntimeGrant{"table", table, "", "SELECT"})
	}
	for _, column := range []string{"installation_id", "activated_postmaster_at", "activated_database_oid"} {
		out = append(out, publicRuntimeGrant{"table", "fleet_trust", column, "SELECT"})
	}
	for _, key := range []struct{ table, column string }{{"fleet_current_trust", "installation_id"}, {"capture_operation_pool", "root_id"}, {"capture_operation_account", "root_id"}, {"capture_operation_audit", "id"}, {"capture_operation_lifecycle", "operation_id"}} {
		out = append(out, publicRuntimeGrant{"table", key.table, key.column, "UPDATE"})
	}
	switch purpose {
	case "capture-cleanup":
		for _, column := range []string{"lease_fence", "lease", "retirement", "certificate_started", "certificate_completion", "terminal_purge", "overdue_selected_at", "overdue_purge"} {
			out = append(out, publicRuntimeGrant{"table", "capture_operation_lifecycle", column, "UPDATE"})
		}
	case "capture-verifier":
		for _, column := range []string{"certificate_verify_attempts", "certificate_receipt", "certificate_acknowledged_at", "terminal_acknowledged_at"} {
			out = append(out, publicRuntimeGrant{"table", "capture_operation_lifecycle", column, "UPDATE"})
		}
	case "capture-finalizer":
		for _, signature := range []string{"finish_capture_operation_retirement(uuid,uuid,uuid)", "finish_capture_operation_history(uuid,text,bytea,timestamptz,timestamptz,uuid)"} {
			out = append(out, publicRuntimeGrant{"function", signature, "", "EXECUTE"})
		}
	}
	return out, true
}
