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
	for _, table := range []string{"context_storage_binding", "custody_pool", "custody_allocation", "retention_policy", "retention_decision"} {
		out = append(out, publicRuntimeGrant{"table", table, "", "SELECT"})
	}
	for _, p := range []struct{ table, column string }{{"context_storage_binding", "source_uid"}, {"custody_pool", "id"}, {"custody_allocation", "id"}} {
		out = append(out, publicRuntimeGrant{"table", p.table, p.column, "UPDATE"}) // row locking only
	}
	return out
}
