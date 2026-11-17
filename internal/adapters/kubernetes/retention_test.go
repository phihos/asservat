package kubernetes

import (
	"context"
	"net/http"
	"strings"
	"testing"
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
func TestRetentionObservationRejectsMalformedPartialAndStaleSources(t *testing.T) {
	for _, mode := range []string{"unknown-field", "case-alias", "duplicate-json", "invalid-selector", "impossible-budget", "page-mismatch", "forbidden"} {
		t.Run(mode, func(t *testing.T) {
			object := retentionObject("baseline", "retention-uid")
			switch mode {
			case "unknown-field":
				object["spec"].(map[string]any)["permissive"] = true
			case "case-alias":
				spec := object["spec"].(map[string]any)
				spec["PurposeRef"] = spec["purposeRef"]
				delete(spec, "purposeRef")
			case "invalid-selector":
				object["spec"].(map[string]any)["scope"] = map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]string{"bad key": "value"}}}
			case "impossible-budget":
				object["spec"].(map[string]any)["deletionBudgetSeconds"] = 3600
			}
			fixture := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, "/evidenceretentionpolicies") {
					return false
				}
				if mode == "forbidden" {
					http.Error(w, "synthetic secret marker", 403)
					return true
				}
				if mode == "duplicate-json" {
					w.Write([]byte(`{"apiVersion":"asservat.io/v1alpha1","kind":"EvidenceRetentionPolicyList","metadata":{"resourceVersion":"one"},"metadata":{"resourceVersion":"two"},"items":[]}`))
					return true
				}
				if mode == "page-mismatch" {
					if r.URL.Query().Get("continue") == "" {
						permissionReply(w, permissionList("EvidenceRetentionPolicy", "one", "next", object))
					} else {
						permissionReply(w, permissionList("EvidenceRetentionPolicy", "two", ""))
					}
					return true
				}
				permissionReply(w, permissionList("EvidenceRetentionPolicy", "one", "", object))
				return true
			})
			c, err := NewRetentionClient(fixture.client)
			if err != nil {
				t.Fatal(err)
			}
			if policies, _, err := c.ListRetentionPolicies(context.Background()); err == nil || len(policies) != 0 {
				t.Fatal("unsafe source returned complete policy")
			}
		})
	}
}
