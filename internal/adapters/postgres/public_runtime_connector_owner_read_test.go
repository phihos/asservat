package postgres

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// native58: the ADR-222 owner-runtime consolidation left federation's
// connector-owner-read without its registry grants, so federation could not
// read fleet_current_trust and never started.
func TestConnectorOwnerReadKeepsRegistryGrants(t *testing.T) {
	grants, ok := publicRuntimeConnectorGrants("connector-owner-read")
	if !ok || len(grants) == 0 {
		t.Fatalf("connector-owner-read grants = %v, %v", grants, ok)
	}
	for _, g := range grants {
		if g == (publicRuntimeGrant{"table", "fleet_current_trust", "", "SELECT"}) {
			return
		}
	}
	t.Fatalf("connector-owner-read lacks SELECT on fleet_current_trust: %v", grants)
}

// A purpose whose grant table is missing falls through to schema USAGE only;
// that login connects but cannot read anything.
func TestEveryRuntimePurposeHasObjectGrants(t *testing.T) {
	for _, purpose := range contracts.PublicRuntimeRolePurposes() {
		grants, ok := publicRuntimeRoleGrants(purpose)
		if !ok || len(grants) < 2 {
			t.Errorf("%s: grants = %v, %v", purpose, grants, ok)
		}
	}
}
