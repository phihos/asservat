package postgres

import (
	"asservat.local/asservat/internal/contracts"
	"slices"
	"strings"
	"testing"
)

func TestOwnerCredentialCombinesIdentityWithoutEvidenceWrites(t *testing.T) {
	const installation = "b62820fb-b202-4d30-9e65-6c0ee2fcfd5e"
	name, ok := OwnerIdentityRoleName(installation, "owner-runtime")
	if !ok || name != "as_b62820fbb2024d309e656c0ee2fcfd5e_own_06" || contracts.OwnerIdentityRoleConnections != 25 {
		t.Fatal("wrong owner role identity or connection envelope", name)
	}
	if _, ok := PublicRuntimeRoleName(installation, "owner-runtime"); ok {
		t.Fatal("owner entered public inventory")
	}
	if _, ok := ConfigurationRuntimeRoleName(installation, "owner-runtime"); ok {
		t.Fatal("owner entered reconciler inventory")
	}
	grants, ok := ownerIdentityRoleGrants("owner-runtime")
	if !ok || len(grants) == 0 || len(OwnerIdentityRoleLayoutDigest()) != 64 {
		t.Fatal("missing exact owner plan")
	}
	for _, required := range []publicRuntimeGrant{
		{"table", "hub_owner_enrollment", "audit_receipt_json", "UPDATE"},
		{"table", "hub_owner_certificate", "activated_at", "UPDATE"},
		{"table", "hub_owner_certificate", "certificate_json", "UPDATE"},
		{"table", "download_worker", "", "SELECT"},
		{"table", "context_catalog", "", "SELECT"},
		{"function", nativeReadConnectorLeaf, "", "EXECUTE"},
	} {
		if !slices.Contains(grants, required) {
			t.Fatal("owner duty lost a required grant", required)
		}
	}
	for i, g := range grants {
		if i > 0 && strings.Compare(grants[i-1].key(), g.key()) >= 0 {
			t.Fatal("noncanonical grant", g)
		}
		if g.kind == "schema" && g.object == "public" && g.privilege == "USAGE" {
			continue
		}
		if g.kind == "function" && g.object == nativeReadConnectorLeaf && g.privilege == "EXECUTE" {
			continue
		}
		if g.kind != "table" {
			t.Fatal("unexpected privilege kind", g)
		}
		if g.privilege == "SELECT" {
			continue
		}
		if g.object == "hub_owner_enrollment" || g.object == "hub_owner_certificate" {
			if g.privilege == "DELETE" || (g.privilege == "INSERT" || g.privilege == "UPDATE") && g.column != "" {
				continue
			}
		}
		// Outside owner identity, the union may only take existing harmless-column
		// row locks. It cannot publish evidence, accept configuration or bind keys.
		lockColumns := map[string]string{"fleet_trust": "installation_id", "fleet_current_trust": "installation_id", "hub_owner_configuration": "source_uid", "download_worker_configuration": "source_uid", "permission_stream": "id", "artifact_download": "id", "download_worker": "id", "download_response": "id", "download_window": "id", "retention_source": "root_id", "download_native_owner": "worker_id"}
		if g.privilege == "UPDATE" && g.column != "" && lockColumns[g.object] == g.column {
			continue
		}
		t.Fatal("owner gained an unrelated effect or broad write", g)
	}
	for _, retired := range []string{"enrollment", "audit", "activation", "registry", "routing", "native-read", "hub-runtime", "configuration-fleet", "", "registry; GRANT ALL"} {
		if _, ok := OwnerIdentityRoleName(installation, retired); ok {
			t.Fatal("unknown or retired owner role accepted", retired)
		}
		if _, ok := ownerIdentityRoleGrants(retired); ok {
			t.Fatal("unknown or retired owner grant plan accepted", retired)
		}
	}
}
