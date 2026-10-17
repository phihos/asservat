package postgres

import (
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestOwnerIdentityRolesKeepSeparateAuthority(t *testing.T) {
	installation := "b62820fb-b202-4d30-9e65-6c0ee2fcfd5e"
	if contracts.OwnerIdentityRoleConnections != 5 || len(OwnerIdentityRoleLayoutDigest()) != 64 {
		t.Fatal("unexpected private role connection envelope")
	}
	seen := map[string]bool{}
	for _, purpose := range contracts.OwnerIdentityRolePurposes() {
		name, ok := OwnerIdentityRoleName(installation, purpose)
		if !ok || seen[name] || len(name) > 63 {
			t.Fatal("invalid or aliased role", purpose)
		}
		seen[name] = true
		if _, ok := PublicRuntimeRoleName(installation, purpose); ok {
			t.Fatal("private owner purpose admitted to public inventory")
		}
		if _, ok := ConfigurationRuntimeRoleName(installation, purpose); ok {
			t.Fatal("private owner purpose admitted to reconciler inventory")
		}
		grants, ok := ownerIdentityRoleGrants(purpose)
		if !ok || len(grants) == 0 {
			t.Fatal("missing role inventory")
		}
		for i, g := range grants {
			if i > 0 && strings.Compare(grants[i-1].key(), g.key()) >= 0 {
				t.Fatal("noncanonical or duplicate grant")
			}
			if g.kind == "schema" {
				if g.object != "public" || g.privilege != "USAGE" {
					t.Fatal("unexpected schema authority", g)
				}
				continue
			}
			// ADR-184 backend pools read their own subsystems; they may only
			// SELECT and take row locks through key columns.
			if purpose == "routing" || purpose == "native-read" {
				if g.kind != "table" || g.privilege != "SELECT" && !(g.privilege == "UPDATE" && slices.Contains([]string{"id", "installation_id", "source_uid", "root_id", "worker_id"}, g.column)) {
					t.Fatal("backend pool can change state", purpose, g)
				}
				continue
			}
			if g.kind != "table" || !slices.Contains([]string{"goose_db_version", "hub_owner_configuration", "hub_owner_configuration_revision", "fleet_current_trust", "hub_owner_enrollment", "hub_owner_certificate"}, g.object) {
				t.Fatal("identity credential reaches a different subsystem", purpose, g)
			}
			if g.privilege == "SELECT" {
				continue
			}
			if g.object == "hub_owner_configuration" && g.column == "source_uid" && g.privilege == "UPDATE" || g.object == "fleet_current_trust" && g.column == "installation_id" && g.privilege == "UPDATE" {
				continue // existing harmless-column row-lock permissions
			}
			switch purpose {
			case "registry":
				t.Fatal("registry can change identity state", g)
			case "audit":
				if g.privilege != "UPDATE" || g.column != "audit_receipt_json" {
					t.Fatal("audit can do more than acknowledge", g)
				}
			case "activation":
				if g.object != "hub_owner_certificate" || g.privilege != "UPDATE" || g.column != "activated_at" {
					t.Fatal("activation can mint or acknowledge a certificate", g)
				}
			case "enrollment":
				if g.column == "audit_receipt_json" || g.column == "activated_at" || g.column == "retired_at" {
					t.Fatal("enrollment can acknowledge, activate or retire itself", g)
				}
			}
		}
	}
	for _, purpose := range []string{"", "configuration-fleet", "capacity", "capture-admit", "registry; GRANT ALL"} {
		if _, ok := OwnerIdentityRoleName(installation, purpose); ok {
			t.Fatal("unrecognized purpose accepted", purpose)
		}
		if _, ok := ownerIdentityRoleGrants(purpose); ok {
			t.Fatal("unrecognized grant inventory", purpose)
		}
	}
	if _, ok := OwnerIdentityRoleName("not-an-installation", "registry"); ok {
		t.Fatal("unvalidated SQL identifier")
	}
}
