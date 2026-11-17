package contracts

import (
	"regexp"
	"slices"
	"testing"
)

var slotName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// Every catalog slot has distinct, valid, fixed source names, so
// the owner Role and workload guard can name all of them at install time.
func TestOwnerClusterSlotNamesCoverEverySlot(t *testing.T) {
	const installation = "11111111-1111-4111-8111-111111111111"
	sources := OwnerPublicGuardedSources(installation)
	if len(sources) != 3+OwnerClusterCatalogSlots {
		t.Fatal("slot names", len(sources))
	}
	all := slices.Clone(sources)
	for i, name := range all {
		if !slotName.MatchString(name) || len(name+"-guard") > 253 || slices.Contains(all[:i], name) {
			t.Fatal("slot name", name)
		}
	}
	for slot := 1; slot <= OwnerClusterCatalogSlots; slot++ {
		if !slices.Contains(sources, OwnerClusterSourceName(installation, slot, "capability")) {
			t.Fatal("slot missing", slot)
		}
	}
}
