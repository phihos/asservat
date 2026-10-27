package postgres

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/migrations"
)

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

// History's permanent custody tables must be accepted during schema replay and
// in the exact final inventory. The embedded migration is the contract source;
// a successful ordinary Goose fixture does not exercise first-install checks.
func TestInitialInstallationInventoryIncludesEncryptedHistoryRelations(t *testing.T) {
	sql, err := fs.ReadFile(migrations.Files(), "00101_history_parameters.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"capture_history_parameter", "capture_history_quota"} {
		if !strings.Contains(string(sql), "CREATE TABLE "+table+" (") {
			t.Fatal("history migration no longer defines expected permanent relation", table)
		}
		if !slices.Contains(initialInstallationTables, table) {
			t.Errorf("first-install exact inventory rejects history relation %q", table)
		}
	}
}
