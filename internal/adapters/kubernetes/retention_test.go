package kubernetes

import (
	"context"
	"net/http"
	"strings"
	"testing"

	value "asservat.local/asservat/internal/domain/privacy"
)

func retentionObject(name, uid string) map[string]any {
	durations := map[string]any{"evidenceSeconds": 3600, "caseMetadataSeconds": 7200, "auditMetadataSeconds": 86400}
	return map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceRetentionPolicy", "metadata": map[string]any{"name": name, "namespace": permissionControl.Name, "uid": uid, "generation": 1, "resourceVersion": "opaque:retention"}, "spec": map[string]any{"scope": map[string]any{}, "purposeRef": "diagnostics", "defaults": durations, "maxima": durations, "rules": []any{}, "deletionBudgetSeconds": 300, "legalExceptions": "disabled"}, "status": map[string]any{"phase": "Ready", "generation": 999}}
}
func TestRetentionListDecodesPoliciesAndIgnoresStatus(t *testing.T) {
	object := retentionObject("baseline", "retention-uid")
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/evidenceretentionpolicies") {
			permissionReply(w, permissionList("EvidenceRetentionPolicy", "opaque:snapshot", "", object))
			return true
		}
		return false
	})
	c, err := NewRetentionClient(f.client)
	if err != nil {
		t.Fatal(err)
	}
	policies, rv, err := c.ListRetentionPolicies(context.Background())
	if err != nil || rv != "opaque:snapshot" || len(policies) != 1 || !policies[0].Policy.Baseline || policies[0].Policy.Revision.UID != "retention-uid" || policies[0].Name != "baseline" {
		t.Fatal("complete baseline", err, rv, policies)
	}
	object["status"] = map[string]any{"phase": "Anything", "observedGeneration": 123}
	again, _, err := c.ListRetentionPolicies(context.Background())
	if err != nil || again[0].Policy.Revision != policies[0].Policy.Revision {
		t.Fatal("status changed the policy", err)
	}
	object["spec"].(map[string]any)["deletionBudgetSeconds"] = 600
	changed, _, err := c.ListRetentionPolicies(context.Background())
	if err != nil || changed[0].Policy.Revision.Digest == policies[0].Policy.Revision.Digest {
		t.Fatal("policy change missing from digest", err)
	}
}

// TestRetentionListKeepsValidPoliciesNextToARejectedOne: one invalid object
// does not block the others; it is returned rejected, with its cluster scope
// when readable and every cluster otherwise.
func TestRetentionListKeepsValidPoliciesNextToARejectedOne(t *testing.T) {
	const cluster = "11111111-1111-4111-8111-111111111111"
	for mode, want := range map[string]string{"unknown-field": value.RejectedSpec, "case-alias": value.RejectedSpec, "invalid-selector": value.RejectedSpec, "impossible-budget": value.RejectedPolicy} {
		t.Run(mode, func(t *testing.T) {
			good, bad := retentionObject("baseline", "good-uid"), retentionObject("bad", "bad-uid")
			spec := bad["spec"].(map[string]any)
			scoped := true
			switch mode {
			case "unknown-field":
				spec["permissive"] = true
			case "case-alias":
				spec["PurposeRef"] = spec["purposeRef"]
				delete(spec, "purposeRef")
			case "invalid-selector":
				spec["scope"] = map[string]any{"clusterIDs": []string{cluster}, "namespaceSelector": map[string]any{"matchLabels": map[string]string{"bad key": "value"}}}
			case "impossible-budget":
				spec["scope"] = map[string]any{"clusterIDs": []string{cluster}}
				spec["deletionBudgetSeconds"] = 3600
			}
			if mode == "unknown-field" || mode == "case-alias" {
				scoped = false
			}
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if strings.HasSuffix(r.URL.Path, "/evidenceretentionpolicies") {
					permissionReply(w, permissionList("EvidenceRetentionPolicy", "one", "", good, bad))
					return true
				}
				return false
			})
			c, err := NewRetentionClient(f.client)
			if err != nil {
				t.Fatal(err)
			}
			policies, _, err := c.ListRetentionPolicies(context.Background())
			if err != nil || len(policies) != 2 {
				t.Fatal("list", err, policies)
			}
			r, ok := policies[0], policies[1]
			if r.Policy.Revision.UID != "bad-uid" {
				r, ok = ok, r
			}
			if ok.Rejected != "" || !ok.Valid() || !ok.Policy.Baseline {
				t.Fatal("valid policy", ok)
			}
			if r.Rejected != want || !r.Valid() || r.Policy.Baseline || (len(r.Scope.ClusterIDs) == 1) != scoped {
				t.Fatal("rejected policy", r)
			}
		})
	}
}
func TestRetentionListFailsOnAnUnreadableList(t *testing.T) {
	for _, mode := range []string{"duplicate-json", "page-mismatch", "forbidden"} {
		t.Run(mode, func(t *testing.T) {
			object := retentionObject("baseline", "retention-uid")
			fixture := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, "/evidenceretentionpolicies") {
					return false
				}
				switch mode {
				case "forbidden":
					http.Error(w, "synthetic secret marker", 403)
				case "duplicate-json":
					w.Write([]byte(`{"apiVersion":"asservat.io/v1alpha1","kind":"EvidenceRetentionPolicyList","metadata":{"resourceVersion":"one"},"metadata":{"resourceVersion":"two"},"items":[]}`))
				default:
					if r.URL.Query().Get("continue") == "" {
						permissionReply(w, permissionList("EvidenceRetentionPolicy", "one", "next", object))
					} else {
						permissionReply(w, permissionList("EvidenceRetentionPolicy", "two", ""))
					}
				}
				return true
			})
			c, err := NewRetentionClient(fixture.client)
			if err != nil {
				t.Fatal(err)
			}
			if policies, _, err := c.ListRetentionPolicies(context.Background()); err == nil || len(policies) != 0 {
				t.Fatal("unreadable list returned policies")
			}
		})
	}
}
