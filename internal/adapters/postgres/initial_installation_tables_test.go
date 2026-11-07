package postgres

import (
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/migrations"
)

// lockInitialTables compares the reviewed inventory directly with PostgreSQL's
// ordered catalog result. A misplaced entry must fail the fast gate, before it
// can prevent every pristine installation from activating.
func TestInitialInstallationInventoryMatchesCatalogOrdering(t *testing.T) {
	if len(initialInstallationTables) == 0 {
		t.Fatal("initial installation inventory is empty")
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

// Policy's new permanent relations also participate in exact installation
// checks and the initial role grants; ordinary Goose tests do not prove this.
func TestInitialInstallationInventoryIncludesPolicyGrantRelations(t *testing.T) {
	sql, err := fs.ReadFile(migrations.Files(), "00102_policy_grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"policy_grant_settings", "policy_grant_attachment", "policy_observation_session"} {
		if !strings.Contains(string(sql), "CREATE TABLE "+table+" (") {
			t.Fatal("policy migration no longer defines expected permanent relation", table)
		}
		if !slices.Contains(initialInstallationTables, table) {
			t.Errorf("first-install exact inventory rejects policy relation %q", table)
		}
	}
	for _, table := range initialTransientTables {
		if slices.Contains(initialInstallationTables, table) {
			t.Errorf("transient relation %q accepted in complete inventory", table)
		}
	}
}

// Every permanent ordinary-source relation must participate in the exact
// catalog inventory used by lockInitialTables before first activation. An
// ordinary migration replay alone cannot exercise that prerequisite.
func TestInitialInstallationInventoryIncludesOrdinarySourceRelation(t *testing.T) {
	sql, err := fs.ReadFile(migrations.Files(), "00105_policy_recording_sources.sql")
	if err != nil {
		t.Fatal(err)
	}
	const table = "policy_recording_source"
	if !strings.Contains(string(sql), "CREATE TABLE "+table+" (") {
		t.Fatal("source migration no longer defines expected permanent relation", table)
	}
	if !slices.Contains(initialInstallationTables, table) {
		t.Errorf("first-install exact catalog inventory rejects ordinary source relation %q", table)
	}
}

// A grouped parent is a permanent control relation. Missing it from the exact
// inventory prevents activation before any group transaction can run.
func TestInitialInstallationInventoryIncludesRecordingSaveGroupRelation(t *testing.T) {
	sql, err := fs.ReadFile(migrations.Files(), "00109_recording_save_groups.sql")
	if err != nil {
		t.Fatal(err)
	}
	const table = "recording_save_group"
	if !strings.Contains(string(sql), "CREATE TABLE "+table+" (") {
		t.Fatal("group migration no longer defines expected relation")
	}
	if !slices.Contains(initialInstallationTables, table) {
		t.Errorf("first-install exact inventory rejects group relation %q", table)
	}
}

// Read the actual143 permanent relations: Goose replay alone does not exercise
// the installer's closed catalog or its compiled preparation/activation scope.
func TestInitialInstallationInventoryIncludesFiniteLiveRelations(t *testing.T) {
	body, err := fs.ReadFile(migrations.Files(), "00143_finite_live_watch.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := strings.Split(string(body), "-- +goose Down")[0]
	matches := regexp.MustCompile(`(?m)^CREATE TABLE (live_watch_[a-z_]+) \(`).FindAllStringSubmatch(up, -1)
	if len(matches) != 3 {
		t.Fatal("unexpected finite live permanent schema", len(matches))
	}
	for _, match := range matches {
		table := match[1]
		if !slices.Contains(initialInstallationTables, table) {
			t.Errorf("first-install exact inventory refuses migrated table %q", table)
		}
		for _, role := range []int{0, 2} {
			grants := initialRoleGrants(role)
			for _, privilege := range []string{"SELECT", "MAINTAIN"} {
				if !slices.Contains(grants, initialRoleGrant{"table", table, "", privilege}) {
					t.Errorf("compiled initial role%d lacks existing %s scope for migrated table %q", role, privilege, table)
				}
			}
			for _, g := range grants {
				if g.object == table && g.privilege != "SELECT" && g.privilege != "MAINTAIN" {
					t.Errorf("initial role%d gained live runtime effects %+v", role, g)
				}
			}
		}
	}
}
