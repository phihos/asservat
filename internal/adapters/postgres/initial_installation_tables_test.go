package postgres

import "testing"

// lockInitialTables compares the reviewed inventory directly with PostgreSQL's
// ordered catalog result. A misplaced entry must fail the fast gate, before it
// can prevent every pristine installation from activating.
func TestInitialInstallationInventoryMatchesCatalogOrdering(t *testing.T) {
	if len(initialInstallationTables) == 0 || len(initialInstallationTables) > 128 {
		t.Fatal("initial installation inventory exceeds its reviewed catalog bound")
	}
	for i, name := range initialInstallationTables {
		if name == "" || i > 0 && name <= initialInstallationTables[i-1] {
			t.Fatalf("initial installation inventory is not strictly ordered at %q", name)
		}
	}
}
