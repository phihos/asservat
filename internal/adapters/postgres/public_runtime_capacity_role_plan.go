package postgres

// The hub-worker's capacity login applies the Helm capacity values and reads
// the stored qualification; the capture login keeps its schema access only.
func publicRuntimeCapacityGrants(purpose string) ([]publicRuntimeGrant, bool) {
	if purpose != "capacity" && purpose != "capacity-capture" {
		return nil, false
	}
	out := []publicRuntimeGrant{{"schema", "public", "", "USAGE"}, {"table", "goose_db_version", "", "SELECT"}}
	if purpose == "capacity" {
		out = append(out, publicRuntimeGrant{"function", "capacity_apply(uuid,uuid,text,text,jsonb,jsonb)", "", "EXECUTE"},
			publicRuntimeGrant{"function", "read_capacity_qualification(uuid)", "", "EXECUTE"})
	}
	return out, true
}
