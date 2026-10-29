package postgres

import "testing"

func TestOrdinarySourceDutyDoesNotAcquireCaptureOrRawGrantPrivileges(t *testing.T) {
	grants, ok := publicRuntimeDutyGrants("policy-automation")
	if !ok {
		t.Fatal("missing existing duty")
	}
	present := map[publicRuntimeGrant]bool{}
	for _, g := range grants {
		present[g] = true
	}
	for _, g := range []publicRuntimeGrant{{"table", "policy_recording_source", "", "INSERT"}, {"table", "policy_acceptance", "observed_bytes_spent", "UPDATE"}, {"table", "capacity_source", "accepted_snapshot", "SELECT"}} {
		if !present[g] {
			t.Fatal("missing source operation privilege", g)
		}
	}
	for _, g := range []publicRuntimeGrant{{"table", "context_capture", "", "INSERT"}, {"table", "policy_recording_source", "", "DELETE"}, {"table", "custody_attempt", "", "INSERT"}, {"table", "access_grant", "policy_observed_bytes_spent", "UPDATE"}, {"table", "capacity_source", "accepted_snapshot", "UPDATE"}, {"table", "capacity_source", "setup_input", "SELECT"}, {"table", "capacity_source", "", "SELECT"}} {
		if present[g] {
			t.Fatal("source duty acquired unrelated authority", g)
		}
	}
}
