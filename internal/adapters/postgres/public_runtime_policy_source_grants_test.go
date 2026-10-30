package postgres

import (
	"slices"
	"testing"
)

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

func TestSnapshotSourceReadDutiesCannotArmOrCreditSources(t *testing.T) {
	for _, purpose := range []string{"capture-admit", "api-execution"} {
		grants, ok := publicRuntimeDutyGrants(purpose)
		if !ok {
			t.Fatal(purpose)
		}
		var source []publicRuntimeGrant
		for _, g := range grants {
			if g.object == "policy_recording_source" {
				source = append(source, g)
			}
		}
		want := []publicRuntimeGrant{{"table", "policy_recording_source", "", "SELECT"}, {"table", "policy_recording_source", "root_id", "UPDATE"}}
		if len(source) != len(want) {
			t.Fatal("source reader gained insertion/credit/terminal/deletion rights", purpose, source)
		}
		for _, g := range want {
			if !slices.Contains(source, g) {
				t.Fatal("missing exact source provenance read/rowlock", purpose, g)
			}
		}
	}
}
