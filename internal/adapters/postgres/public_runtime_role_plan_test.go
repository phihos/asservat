package postgres

import (
	"fmt"
	"slices"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestPublicRuntimeRolePlanKeepsPurposeIdentityAndProjection(t *testing.T) {
	const installation = "10000000-0000-4000-8000-000000000001"
	wantHub := []string{"hub-runtime", "worker-config-read", "capacity-profile-read", "capture-admit"}
	want := append(slices.Clone(wantHub), "connector-delivery", "connector-owner-read", "capacity", "capacity-capture", "permission-accept", "permission-audit", "retention-source", "retention-lifecycle-audit", "worker-config-observe", "worker-config-audit", "context-cleanup", "context-cleanup-audit", "context-cleanup-finalize", "key-configuration", "key-wrap", "key-acquisition")
	// ADR-204 takes the next unused ordinals 86-88, ADR-205 89-91 and ADR-210
	// 92; metadata uses 93 and execution 94; old facet ordinals (including the
	// removed publisher 24-27 and 65 and key-verify 84) remain retired.
	ordinals := []int{95, 20, 34, 40, 52, 56, 70, 71, 72, 73, 78, 81, 86, 87, 89, 90, 91, 82, 83, 88}
	for n, purpose := range want {
		ordinal, known := contracts.PublicRuntimeRoleOrdinal(purpose)
		name, valid := PublicRuntimeRoleName(installation, purpose)
		if !known || !valid || ordinal != ordinals[n] || len(name) > 63 || name != fmt.Sprintf("as_10000000000040008000000000000001_pub_%02d", ordinals[n]) {
			t.Fatalf("fixed purpose identity changed: %s", purpose)
		}
		limit, known := contracts.PublicRuntimeRoleConnectionLimit(purpose)
		wantLimit := 5
		if purpose == "hub-runtime" {
			wantLimit = 81
		}
		if n >= len(wantHub) {
			wantLimit = 3
		}
		if slices.Contains(contracts.PublicRuntimeFederationPurposes(), purpose) {
			wantLimit = -1
		}
		if !known || limit != wantLimit {
			t.Fatalf("wrong fixed connection compartment: %s", purpose)
		}
	}
	before := PublicRuntimeRoleLayoutDigest()
	roles, projection := contracts.PublicRuntimeRolePurposes(), contracts.PublicRuntimeHubRolePurposes()
	roles[0], projection[0] = "capacity", "capacity-capture"
	if !slices.Equal(contracts.PublicRuntimeRolePurposes(), want) || !slices.Equal(contracts.PublicRuntimeHubRolePurposes(), wantHub) || PublicRuntimeRoleLayoutDigest() != before {
		t.Fatal("caller mutation changed source-owned role inventory")
	}
	for _, unknown := range []string{"browser-cleanup", "worker-owner", "capacity-arbitrary", "capture-source", "administrator", "identity-read ", "identity-read; DROP ROLE postgres"} {
		if _, known := contracts.PublicRuntimeRoleOrdinal(unknown); known {
			t.Fatalf("unimplemented purpose acquired an ordinal: %s", unknown)
		}
		if _, known := publicRuntimeRoleGrants(unknown); known {
			t.Fatalf("unimplemented purpose acquired grants: %s", unknown)
		}
	}
}

func TestPublicDownloadSourceRoleReadsReceiptsWithoutEffectPrivileges(t *testing.T) {
	grants, ok := publicRuntimeDutyGrants("download-source")
	if !ok {
		t.Fatal("missing fixed source role")
	}
	for _, table := range []string{"custody_copy", "context_case_locator"} {
		if !slices.Contains(grants, publicRuntimeGrant{"table", table, "", "SELECT"}) {
			t.Fatalf("missing exact source read: %s", table)
		}
	}
	for _, g := range grants {
		if g.privilege == "SELECT" || g.kind == "schema" {
			continue
		}
		if g.privilege == "UPDATE" && (g.object == "fleet_current_trust" && g.column == "installation_id" || g.object == "permission_stream" && g.column == "id") {
			continue
		}
		t.Fatalf("source role gained an effect grant: %+v", g)
	}
}

// This is a closed allow-list, including lock columns. A broad table grant or
// an extra privilege must fail even if the positive use case still works.
func TestPublicContextDraftRolesHaveExactPurposeGrants(t *testing.T) {
	common := []publicRuntimeGrant{{"schema", "public", "", "USAGE"}, {"table", "goose_db_version", "", "SELECT"}}
	previews := append(slices.Clone(common),
		// SQL108: passive source references and shared preview-budget sets.
		publicRuntimeGrant{"table", "recording_selection_set", "", "SELECT"},
		publicRuntimeGrant{"table", "recording_selection_set", "", "INSERT"},
		publicRuntimeGrant{"table", "recording_selection_set", "", "DELETE"},
		publicRuntimeGrant{"table", "policy_recording_source", "", "SELECT"},
		publicRuntimeGrant{"table", "policy_source", "", "SELECT"},
		publicRuntimeGrant{"table", "permission_stream", "", "SELECT"},
		publicRuntimeGrant{"table", "permission_stream", "id", "UPDATE"},
		publicRuntimeGrant{"table", "workload_name", "", "SELECT"},
		publicRuntimeGrant{"table", "workload_name", "", "INSERT"})
	for purpose, want := range map[string][]publicRuntimeGrant{"capture-preview": previews} {
		t.Run(purpose, func(t *testing.T) {
			got, ok := publicRuntimeDutyGrants(purpose)
			keys := func(v []publicRuntimeGrant) []string {
				out := make([]string, len(v))
				for n, g := range v {
					out[n] = g.key()
				}
				slices.Sort(out)
				return out
			}
			if !ok || !slices.Equal(keys(got), keys(want)) {
				t.Fatalf("purpose grants differ: got %v, want %v", keys(got), keys(want))
			}
		})
	}
}
