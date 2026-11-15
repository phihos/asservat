package postgres

// Fixed SQL54 compartment RPCs copied from the reviewed V6 adapter corpus.
// This is a compiled allowlist; neither a projected document nor caller may
// choose a signature. No private helper or capacity/audit table grant. The
// general facet additionally reads the fixed owner registry before disclosing
// its local projected observation token; it cannot issue or activate peers.
func publicRuntimeCapacityGrants(purpose string) ([]publicRuntimeGrant, bool) {
	var signatures []string
	switch purpose {
	case "capacity":
		signatures = []string{
			"read_capacity_runtime_scope(uuid,jsonb,jsonb,timestamptz,timestamptz)",
			"read_capacity_permission_scopes(uuid,jsonb)",
			"read_capacity_source_revision(uuid,jsonb)",
			"accept_capacity_source(uuid,bigint,jsonb,jsonb,jsonb,uuid,bytea)",
			"invalidate_capacity_source(uuid,bigint,jsonb,timestamptz,timestamptz)",
			"read_capacity_root(uuid,jsonb,bytea,bytea)",
			"reserve_capacity_root(uuid,jsonb,bytea,bytea,uuid)",
			"publish_capacity_root(uuid,jsonb,bytea,bytea,jsonb)",
			"renew_capacity_root(uuid,jsonb,bytea,bytea,jsonb)",
			"read_capacity_enrollment(uuid,jsonb,bytea,bytea,bytea)",
			"reserve_capacity_enrollment(uuid,jsonb,bytea,bytea,bytea,uuid,uuid,uuid,uuid,bytea)",
			"publish_capacity_enrollment(uuid,jsonb,bytea,bytea,bytea,jsonb)",
			"continue_capacity_publication(uuid,jsonb,bytea,bytea,bytea,jsonb)",
			"refresh_capacity_enrollment(uuid,jsonb,bytea,bytea,bytea,jsonb)",
			// ADR-197: the regional namespace pins.
			"read_capacity_cluster_qualifications(uuid)",
			// ADR-331: the joined clusters' write-once qualifications.
			"qualify_capacity_cluster(uuid,uuid,uuid,uuid,bytea,jsonb)",
			// ADR-200: active refresh demands.
			"read_capacity_refresh_demands(uuid)",
			// ADR-219: shared query backing follows these existing publications.
			"ensure_shared_context_query_capacity(uuid)",
			"ensure_shared_context_query_allocation(uuid,uuid,text,text)",
			// Helm-native decision 6: the hub-worker initializes the root.
			"initialize_capacity_source(uuid,uuid,text,bytea,text,jsonb)",
			"read_capacity_qualification(uuid)",
		}
	case "capacity-capture":
		signatures = []string{
			"read_capacity_runtime_scope(uuid,jsonb,jsonb,timestamptz,timestamptz)",
			"read_capacity_capture_enrollment(uuid,jsonb,bytea,bytea,bytea)",
			"back_capacity_root(uuid,jsonb,bytea,bytea,jsonb)",
			"back_capacity_enrollment(uuid,jsonb,bytea,bytea,bytea,jsonb)",
			"continue_capacity_capture(uuid,jsonb,bytea,bytea,bytea,jsonb)",
		}
	default:
		return nil, false
	}
	// Both facets read the fleet trust row for the SQL functions' trust input.
	out := []publicRuntimeGrant{{"schema", "public", "", "USAGE"}, {"table", "goose_db_version", "", "SELECT"}, {"table", "fleet_current_trust", "", "SELECT"}}
	if purpose == "capacity" {
		// Exact read graph of OwnerEnrollments.current(false),
		// ReadContextStartOwners and ReadOwnerRegistration. The column UPDATE
		// grant permits the existing FOR SHARE lock. No certificate/configuration
		// effect column, enrollment INSERT, DELETE or activation function is granted.
		for _, table := range []string{"hub_owner_configuration", "hub_owner_configuration_revision", "hub_owner_enrollment", "hub_owner_certificate"} {
			out = append(out, publicRuntimeGrant{"table", table, "", "SELECT"})
		}
		out = append(out,
			publicRuntimeGrant{"table", "hub_owner_configuration", "source_uid", "UPDATE"},
			// ADR-331: the joined clusters' delivered capacity observations.
			publicRuntimeGrant{"table", "remote_capacity_delivery", "", "SELECT"})
	}
	for _, signature := range signatures {
		out = append(out, publicRuntimeGrant{"function", signature, "", "EXECUTE"})
	}
	return out, true
}
