package postgres

import (
	"slices"
	"testing"
)

func TestCapacityRolesHaveExactGrants(t *testing.T) {
	base := []publicRuntimeGrant{{"schema", "public", "", "USAGE"}, {"table", "goose_db_version", "", "SELECT"}}
	want := map[string][]publicRuntimeGrant{
		"capacity-capture": base,
		"capacity": append(slices.Clone(base), publicRuntimeGrant{"function", "capacity_apply(uuid,uuid,text,text,jsonb,jsonb)", "", "EXECUTE"},
			publicRuntimeGrant{"function", "read_capacity_qualification(uuid)", "", "EXECUTE"}),
	}
	for purpose, w := range want {
		if got, ok := publicRuntimeRoleGrants(purpose); !ok || !slices.Equal(got, w) {
			t.Fatal("capacity grants changed", purpose, got)
		}
	}
}
