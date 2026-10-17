package postgres

import "testing"

func TestInitialBootstrapHistoryTransferPreservesMeasuredOwnerOrigins(t *testing.T) {
	const manager uint32 = 1234
	var original []initialHistoryOrigin
	for i, g := range initialHistoryGrants() {
		owner := uint32(10)
		if i == 0 {
			owner = 6171
		}
		original = append(original, initialHistoryOrigin{grant: g, owner: owner, grantor: manager})
	}
	if !initialHistoryOriginSet(original, manager, false) || initialHistoryOriginSet(original, manager, true) {
		t.Fatal("original manager origins not distinguished")
	}
	moved := append([]initialHistoryOrigin(nil), original...)
	for i := range moved {
		moved[i].grantor = moved[i].owner
	}
	if !initialHistoryOriginSet(moved, manager, true) || initialHistoryOriginSet(moved, manager, false) {
		t.Fatal("exact measured-owner origins not distinguished")
	}
	for _, edit := range []func([]initialHistoryOrigin){
		func(v []initialHistoryOrigin) { v[0].grantor = 10 },
		func(v []initialHistoryOrigin) { v[1].grantor = manager },
		func(v []initialHistoryOrigin) { v[1] = v[0] },
		func(v []initialHistoryOrigin) { v[0].owner = manager },
		func(v []initialHistoryOrigin) { v[0].grant.privilege = "CREATE" },
		func(v []initialHistoryOrigin) { v[2].grant.object = "foreign" },
	} {
		v := append([]initialHistoryOrigin(nil), moved...)
		edit(v)
		if initialHistoryOriginSet(v, manager, true) {
			t.Fatal("changed history grant set accepted")
		}
	}
	if initialHistoryOriginSet(append(moved, moved[0]), manager, true) || initialHistoryOriginSet(moved[:2], manager, true) {
		t.Fatal("extra or missing privilege accepted")
	}
	if original[0].grantor != manager {
		t.Fatal("original provenance mutated")
	}
}
