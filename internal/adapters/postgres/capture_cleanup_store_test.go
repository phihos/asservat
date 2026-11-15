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
