package postgres

// The shared acquisition process uses its existing worker credential for query
// admission, immutable identity and native binding. A-KEY can only consume the
// exact existing key child. This adds no login or cross-process credential mount.
func publicRuntimeProjectionGrants(purpose string) []publicRuntimeGrant {
	var out []publicRuntimeGrant
	add := func(table, privilege string, columns ...string) {
		if len(columns) == 0 {
			out = append(out, publicRuntimeGrant{"table", table, "", privilege})
			return
		}
		for _, column := range columns {
			out = append(out, publicRuntimeGrant{"table", table, column, privilege})
		}
	}
	function := func(name string) { out = append(out, publicRuntimeGrant{"function", name, "", "EXECUTE"}) }
	switch purpose {
	case "capacity-profile-read":
		function("read_shared_context_query_plan(uuid,uuid,text,text,jsonb,bytea,uuid,jsonb)")
		return out
	case "worker-enrollment", "worker-enrollment-activate":
		add("context_query", "SELECT")
		add("context_query", "UPDATE", "id")
		return out
	case "download-worker", "key-acquisition":
	default:
		return nil
	}
	for _, table := range []string{"context_case_locator", "operation_audit", "operation_audit_lifecycle", "context_query_backing", "context_query_allocation", "context_query_principal", "context_query", "context_query_call", "context_query_worker", "context_query_batch", "context_query_key_binding"} {
		add(table, "SELECT")
	}
	for _, table := range []string{"operation_audit", "context_query_allocation", "context_query_principal", "context_query"} {
		add(table, "UPDATE", "id")
	}
	add("operation_audit_lifecycle", "UPDATE", "operation_id")
	add("context_query_backing", "UPDATE", "root_id")
	add("context_query_batch", "UPDATE", "id")
	function("lock_context_query_capacity(uuid,uuid)")
	function("context_query_capacity_allocation_current(uuid,uuid)")
	function("context_query_shared_profile_current(uuid,jsonb)")
	if purpose == "key-acquisition" {
		// queryIntentFence binds the paid invocation to the original database
		// incarnation; the current-trust view does not expose these columns.
		add("fleet_trust", "SELECT", "installation_id", "activated_postmaster_at", "activated_database_oid")
		add("context_query_key_binding", "UPDATE", "used_roles")
		return out
	}
	for _, table := range []string{"context_query_principal", "context_query", "context_query_call", "context_query_batch", "context_query_worker", "context_query_key_binding"} {
		add(table, "INSERT")
	}
	add("context_query_batch", "UPDATE", "claim_id", "closed", "native_operation", "native_authority", "native_closed")
	add("download_allocation", "SELECT")
	add("download_worker", "INSERT", "query_id", "query_allocation_id")
	add("download_worker", "UPDATE", "audit_receipt_json", "id", "abandoned_at")
	return out
}
