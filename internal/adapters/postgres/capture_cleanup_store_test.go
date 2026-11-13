package postgres

import "testing"

func TestCaptureCleanupStoreRequiresOneSharedLaneStore(t *testing.T) {
	a, b := "10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002"
	if got, err := captureCleanupStore(&a, &a, &a); err != nil || got != a {
		t.Fatal("shared lane store refused", err)
	}
	bad := "invalid"
	for _, lanes := range [][3]*string{{&a, &b, &a}, {&a, &a, &b}, {nil, &a, &a}, {&bad, &bad, &bad}} {
		if _, err := captureCleanupStore(lanes[0], lanes[1], lanes[2]); err == nil {
			t.Fatal("mismatched or missing lane store accepted")
		}
	}
}

func TestCaptureCleanupReadsOnlyQualificationOfCapacitySource(t *testing.T) {
	for _, purpose := range []string{"capture-cleanup", "capture-verifier", "capture-finalizer"} {
		grants, _ := publicRuntimeCaptureCleanupGrants(purpose)
		var columns []string
		for _, g := range grants {
			if g.object == "capacity_source" {
				if g.privilege != "SELECT" {
					t.Fatal("cleanup writes capacity source", purpose, g.key())
				}
				columns = append(columns, g.column)
			}
		}
		if len(columns) != 2 || columns[0] != "root_id" || columns[1] != "qualification" {
			t.Fatal("cleanup capacity source read is not the store lookup", purpose, columns)
		}
	}
}
