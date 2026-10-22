package postgres

import (
	"fmt"
	"slices"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestPublicRuntimeRolePlanKeepsPurposeIdentityAndProjection(t *testing.T) {
	const installation = "10000000-0000-4000-8000-000000000001"
	wantHub := []string{"identity-read", "browser-settings", "browser-session", "browser-cleanup", "refresh-admit", "refresh-owner", "refresh-read", "hub-metadata-read", "capture-intent-read", "download-source", "download-plan", "worker-config-read", "audit-normal-journal", "audit-normal-ack", "audit-resolution-journal", "audit-resolution-ack", "capacity-profile-read", "capture-admit", "capture-journal", "capture-ack", "capture-preview", "capture-resolution", "api-execution", "download-session", "download-audit", "download-worker", "download-worker-audit", "download-worker-identity", "worker-enrollment", "worker-enrollment-audit", "worker-enrollment-activate", "worker-owner", "native-owner", "download-key-bind", "native-key-bind", "download-stop", "download-stop-writer", "download-stop-ack", "fleet-bootstrap-reserve", "fleet-bootstrap-record", "fleet-bootstrap-audit", "fleet-bootstrap-activate", "regional-capacity", "processing-decision"}
	want := append(slices.Clone(wantHub), "capture-cleanup", "capture-verifier", "capture-finalizer", "connector-source", "connector-journal", "connector-ack", "connector-read", "cluster-credential", "connector-owner-read", "publication-gate", "context-verify", "context-verification-audit", "context-publish", "publisher-identity-read", "publisher-retention-read", "connector-cleanup", "connector-verifier", "connector-finalizer", "capacity", "capacity-capture", "permission-accept", "permission-audit", "retention-source", "retention-source-audit", "retention-catchup", "retention-lifecycle-audit", "worker-config-observe", "worker-config-audit", "context-cleanup", "context-cleanup-audit", "context-cleanup-finalize", "key-configuration", "key-wrap", "key-verify", "key-acquisition")
	// ADR-204 takes the next unused ordinals 86-88, ADR-205 89-91 and ADR-210
	// 92; metadata uses 93 and execution 94; old facet ordinals remain retired.
	ordinals := []int{0, 1, 2, 3, 4, 5, 6, 93, 16, 17, 19, 20, 30, 31, 32, 33, 34, 40, 41, 42, 46, 47, 94, 28, 29, 35, 36, 37, 38, 39, 57, 58, 59, 60, 61, 62, 63, 64, 74, 75, 76, 77, 85, 92, 43, 44, 45, 48, 49, 50, 51, 52, 56, 24, 25, 26, 27, 65, 66, 53, 54, 55, 70, 71, 72, 73, 78, 79, 80, 81, 86, 87, 89, 90, 91, 82, 83, 84, 88}
	for n, purpose := range want {
		ordinal, known := contracts.PublicRuntimeRoleOrdinal(purpose)
		name, valid := PublicRuntimeRoleName(installation, purpose)
		if !known || !valid || ordinal != ordinals[n] || len(name) > 63 || name != fmt.Sprintf("as_10000000000040008000000000000001_pub_%02d", ordinals[n]) {
			t.Fatalf("fixed purpose identity changed: %s", purpose)
		}
		limit, known := contracts.PublicRuntimeRoleConnectionLimit(purpose)
		wantLimit := 5
		if purpose == "hub-metadata-read" {
			wantLimit = 29
		}
		if purpose == "api-execution" {
			wantLimit = 13
		}
		if n >= len(wantHub) {
			wantLimit = 3
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
	for _, unknown := range []string{"capacity-arbitrary", "capture-source", "administrator", "identity-read ", "identity-read; DROP ROLE postgres"} {
		if _, known := contracts.PublicRuntimeRoleOrdinal(unknown); known {
			t.Fatalf("unimplemented purpose acquired an ordinal: %s", unknown)
		}
		if _, known := publicRuntimeRoleGrants(unknown); known {
			t.Fatalf("unimplemented purpose acquired grants: %s", unknown)
		}
	}
}

func TestPublicDownloadSourceRoleReadsReceiptsWithoutEffectPrivileges(t *testing.T) {
	grants, ok := publicRuntimeRoleGrants("download-source")
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
		if g.privilege == "UPDATE" && (g.object == "fleet_current_trust" && g.column == "installation_id" || g.object == "permission_stream" && g.column == "id" || g.object == "retention_source" && g.column == "root_id") {
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
		publicRuntimeGrant{"table", "permission_stream", "", "SELECT"},
		publicRuntimeGrant{"table", "context_preview", "", "SELECT"},
		publicRuntimeGrant{"table", "context_preview_fence", "", "SELECT"},
		publicRuntimeGrant{"table", "permission_stream", "id", "UPDATE"},
		publicRuntimeGrant{"table", "context_preview", "", "INSERT"},
		publicRuntimeGrant{"table", "context_preview", "", "DELETE"},
		publicRuntimeGrant{"table", "context_preview_fence", "", "DELETE"},
		// ADR-200: a refresh demand, no table grant.
		publicRuntimeGrant{"function", "demand_capacity_refresh(uuid,uuid,text,text,text,text,text)", "", "EXECUTE"})
	resolution := append(slices.Clone(common),
		publicRuntimeGrant{"table", "fleet_current_trust", "", "SELECT"},
		publicRuntimeGrant{"table", "permission_stream", "", "SELECT"},
		publicRuntimeGrant{"table", "permission_basis", "", "SELECT"},
		publicRuntimeGrant{"table", "permission_assignment", "", "SELECT"},
		publicRuntimeGrant{"table", "authority_audit", "", "SELECT"},
		publicRuntimeGrant{"table", "context_capture", "", "SELECT"},
		publicRuntimeGrant{"table", "context_preview", "", "SELECT"},
		publicRuntimeGrant{"table", "context_preview_fence", "", "SELECT"},
		publicRuntimeGrant{"table", "fleet_current_trust", "installation_id", "UPDATE"},
		publicRuntimeGrant{"table", "permission_stream", "id", "UPDATE"},
		publicRuntimeGrant{"table", "context_preview", "closed_at", "UPDATE"},
		publicRuntimeGrant{"table", "context_preview", "closed_request_key", "UPDATE"},
		publicRuntimeGrant{"table", "context_preview", "closed_submission_digest", "UPDATE"},
		publicRuntimeGrant{"table", "context_preview_fence", "", "INSERT"},
		publicRuntimeGrant{"table", "context_preview", "", "DELETE"},
		publicRuntimeGrant{"table", "context_preview_fence", "", "DELETE"})
	for purpose, want := range map[string][]publicRuntimeGrant{"capture-preview": previews, "capture-resolution": resolution} {
		t.Run(purpose, func(t *testing.T) {
			got, ok := publicRuntimeRoleGrants(purpose)
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
