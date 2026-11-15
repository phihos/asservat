package postgres

// publicRuntimeConnectorGrants is the fixed SQL49/51 connector duty layout
// (ADR-170): the federation's recovery, delivery and owner reads.
func publicRuntimeConnectorGrants(purpose string) ([]publicRuntimeGrant, bool) {
	out := []publicRuntimeGrant{{"schema", "public", "", "USAGE"}, {"table", "goose_db_version", "", "SELECT"}}
	switch purpose {
	case "connector-read":
		// The recovery state the owner reads answer.
		out = append(out, publicRuntimeGrant{"table", "fleet_current_trust", "", "SELECT"})
	case "connector-delivery":
		// ADR-329: the presenting connector's AccessBinding delivery, stored
		// under the cluster its ServiceAccount token was attributed to.
		for _, privilege := range []string{"SELECT", "INSERT", "UPDATE"} {
			out = append(out, publicRuntimeGrant{"table", "remote_access_binding_delivery", "", privilege})
			// ADR-331: likewise its capacity observation.
			out = append(out, publicRuntimeGrant{"table", "remote_capacity_delivery", "", privilege})
		}
	case "connector-owner-read":
		// ADR-172: the hub-api owner registry reads, for owner discovery and
		// authentication on behalf of regions. No owner write is granted.
		return ownerIdentityDutyGrants("registry")
	default:
		return nil, false
	}
	return out, true
}
