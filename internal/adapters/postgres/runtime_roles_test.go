package postgres

import (
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// Every login the secrets hook writes into `<name>-sql-<component>` is
// created by setup with its compiled grants (decision 9), including the
// cleanup lanes' capacity_source columns and hub-api's qualification pin.
func TestRuntimeRolesCoverEveryMountedComponentLogin(t *testing.T) {
	installation := "10000000-0000-4000-8000-000000000001"
	roles, err := RuntimeRoles(installation)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]RuntimeRole{}
	for _, r := range roles {
		byName[r.Name] = r
	}
	name := func(purpose string) string {
		for _, f := range []func(string, string) (string, bool){PublicRuntimeRoleName, ConfigurationRuntimeRoleName, OwnerIdentityRoleName} {
			if n, ok := f(installation, purpose); ok {
				return n
			}
		}
		return ""
	}
	grant := func(purpose string, g publicRuntimeGrant) bool {
		for _, have := range byName[name(purpose)].grants {
			if have == g {
				return true
			}
		}
		return false
	}
	for _, component := range contracts.SQLComponents() {
		purposes, ok := contracts.SQLComponentPurposes(component)
		if !ok || len(purposes) == 0 {
			t.Fatal("component", component)
		}
		for _, purpose := range purposes {
			if _, ok := byName[name(purpose)]; !ok {
				t.Errorf("%s login %s has no compiled role", component, purpose)
			}
		}
	}
	for _, purpose := range []string{"capture-cleanup", "capture-verifier", "capture-finalizer"} {
		if !grant(purpose, publicRuntimeGrant{"table", "capacity_source", "root_id", "SELECT"}) || !grant(purpose, publicRuntimeGrant{"table", "capacity_source", "qualification", "SELECT"}) {
			t.Error("cleanup lane lacks capacity_source(root_id, qualification)", purpose)
		}
	}
	if !grant("capacity-profile-read", publicRuntimeGrant{"function", "read_capacity_qualification_pin(uuid,uuid)", "", "EXECUTE"}) {
		t.Error("hub-api cannot read the capacity qualification pin")
	}
}

func TestRuntimeRolesCoverAllCompiledPlansWithUniqueNames(t *testing.T) {
	installation := "10000000-0000-4000-8000-000000000001"
	roles, err := RuntimeRoles(installation)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "as_" + strings.ReplaceAll(installation, "-", "") + "_"
	seen := map[string]bool{}
	var pub, configuration, owner int
	for _, r := range roles {
		if seen[r.Name] || !strings.HasPrefix(r.Name, prefix) || len(r.Name) > 63 || r.Connections < 1 || len(r.grants) == 0 {
			t.Fatalf("invalid runtime role %+v", r)
		}
		seen[r.Name] = true
		switch r.Name[len(prefix) : len(prefix)+4] {
		case "pub_":
			pub++
		case "cfg_":
			configuration++
		case "own_":
			owner++
		}
	}
	if pub == 0 || configuration != 3 || owner != 1 {
		t.Fatal("inventory", pub, configuration, owner)
	}
	if _, err = RuntimeRoles("not-a-uuid"); err == nil {
		t.Fatal("invalid installation accepted")
	}
}

func TestSQLPasswordVerifierRejectsWeakPasswords(t *testing.T) {
	for _, p := range []string{"", "short", strings.Repeat("a", 31), strings.Repeat("a", 40) + " ", strings.Repeat("a", 1025)} {
		if _, err := sqlPasswordVerifier(SQLLogin{Username: "as_x", Password: p}); err == nil {
			t.Fatalf("accepted %q", p)
		}
	}
	v, err := sqlPasswordVerifier(SQLLogin{Username: "as_x", Password: strings.Repeat("Ab1-", 11)})
	if err != nil || !strings.HasPrefix(v, "SCRAM-SHA-256$4096:") || strings.Contains(v, "Ab1-") {
		t.Fatal(v, err)
	}
}

func TestEmbeddedSchemaAndHistoryPrefix(t *testing.T) {
	b, err := EmbeddedSchema()
	if err != nil || b.Head != CompiledSchemaVersion || len(b.Digest) != 64 {
		t.Fatal(b, err)
	}
	ok := []schemaVersion{{1, 0, true}, {2, 1, true}, {3, 2, true}}
	if head, err := schemaPrefix(ok, 5); err != nil || head != 2 {
		t.Fatal(head, err)
	}
	for _, bad := range [][]schemaVersion{
		{},
		{{1, 0, true}, {2, 2, true}},
		{{1, 0, true}, {2, 1, false}},
		{{2, 0, true}, {1, 1, true}},
		{{1, 0, true}, {2, 1, true}, {3, 2, true}},
	} {
		if _, err := schemaPrefix(bad, 1); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}
