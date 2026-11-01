package postgres

// Source-purpose extension of the existing policy-automation duty. No new
// credential or role ordinal, configuration writer, capture or object grant.
func publicRuntimePolicySourceGrants() []publicRuntimeGrant {
	out := []publicRuntimeGrant{
		{"table", "policy_recording_source", "", "SELECT"},
		{"table", "policy_recording_source", "", "INSERT"},
		{"table", "policy_recording_source", "credit", "UPDATE"},
		{"table", "policy_recording_source", "ended_at", "UPDATE"},
		{"table", "policy_recording_source", "slot_released_at", "UPDATE"},
		{"table", "policy_acceptance", "observed_bytes_spent", "UPDATE"},
		{"function", "capacity_managed_admission_until(uuid,uuid,text,timestamptz)", "", "EXECUTE"},
	}
	for _, table := range []string{"context_storage_binding", "custody_pool", "custody_allocation", "context_control_pool", "context_control_account", "retention_source", "retention_checkpoint", "retention_catchup", "retention_catchup_effect", "retention_decision"} {
		out = append(out, publicRuntimeGrant{"table", table, "", "SELECT"})
	}
	for _, p := range []struct{ table, column string }{{"context_storage_binding", "source_uid"}, {"custody_pool", "id"}, {"custody_allocation", "id"}, {"context_control_pool", "root_id"}, {"context_control_account", "root_id"}, {"retention_source", "root_id"}, {"capacity_source", "root_id"}, {"capacity_workload", "id"}} {
		out = append(out, publicRuntimeGrant{"table", p.table, p.column, "UPDATE"}) // row locking only
	}
	// Public accepted-source columns only; private setup/root/provider inputs
	// remain unavailable to this duty.
	for _, column := range []string{"root_id", "accepted_revision", "accepted_snapshot", "accepted_digest", "observed_at", "fresh_until", "suspended"} {
		out = append(out, publicRuntimeGrant{"table", "capacity_source", column, "SELECT"})
	}
	for _, column := range []string{"root_id", "allocation_id", "policy_uid", "ready_at", "mutation_xid"} {
		out = append(out, publicRuntimeGrant{"table", "capacity_workload", column, "SELECT"})
	}
	return out
}
