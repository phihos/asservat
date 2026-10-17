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
			"read_capacity_recovery(uuid,timestamptz,timestamptz)",
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
	out := []publicRuntimeGrant{{"schema", "public", "", "USAGE"}, {"table", "goose_db_version", "", "SELECT"}}
	if purpose == "capacity" {
		// Exact read graph of OwnerEnrollments.current(false),
		// ReadContextStartOwners and ReadOwnerRegistration. The two column
		// UPDATE grants permit existing FOR SHARE locks; immutable-key and
		// recovery guards remain enforced. No certificate/configuration effect
		// column, enrollment INSERT, DELETE or activation function is granted.
		for _, table := range []string{"fleet_current_trust", "hub_owner_configuration", "hub_owner_configuration_revision", "hub_owner_enrollment", "hub_owner_certificate"} {
			out = append(out, publicRuntimeGrant{"table", table, "", "SELECT"})
		}
		out = append(out,
			publicRuntimeGrant{"table", "fleet_current_trust", "installation_id", "UPDATE"},
			publicRuntimeGrant{"table", "hub_owner_configuration", "source_uid", "UPDATE"})
	}
	for _, signature := range signatures {
		out = append(out, publicRuntimeGrant{"function", signature, "", "EXECUTE"})
	}
	return out, true
}
