package postgres

import (
	"slices"
	"testing"
)

// The installed worker consumes this exact compiled profile. It needs metadata
// for bounded pruning, never provider credentials or session creation rights.
func TestBrowserSettingsRoleSupportsBoundedCredentialCleanup(t *testing.T) {
	grants, ok := publicRuntimeRoleGrants("browser-settings")
	if !ok {
		t.Fatal("missing installed settings role")
	}
	for table, columns := range map[string][]string{
		"browser_login":   {"root_id", "id", "epoch", "expires_at"},
		"browser_session": {"root_id", "id", "epoch", "expires_at", "claim_until"},
		"browser_logout":  {"root_id", "id", "epoch", "expires_at"},
	} {
		for _, column := range columns {
			if !slices.Contains(grants, publicRuntimeGrant{"table", table, column, "SELECT"}) {
				t.Fatalf("pruning cannot read required metadata %s.%s", table, column)
			}
		}
		if !slices.Contains(grants, publicRuntimeGrant{"table", table, "", "DELETE"}) {
			t.Fatalf("cannot delete expired %s", table)
		}
		// FOR UPDATE needs an UPDATE privilege even though pruning only deletes.
		if !slices.Contains(grants, publicRuntimeGrant{"table", table, "id", "UPDATE"}) && table != "browser_session" {
			t.Fatalf("cannot lock pruning candidates %s", table)
		}
	}
	for _, g := range grants {
		if g.kind != "table" || g.object != "browser_session" && g.object != "browser_login" && g.object != "browser_logout" {
			continue
		}
		if g.privilege == "INSERT" || g.privilege == "SELECT" && (g.column == "" || g.column == "ciphertext") || g.privilege == "UPDATE" && (g.column == "" || g.column == "ciphertext") {
			t.Fatalf("cleanup gained credential access: %+v", g)
		}
	}
}
