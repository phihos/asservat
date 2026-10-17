package kubernetes

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func retentionObject(name, uid string) map[string]any {
	durations := map[string]any{"evidenceSeconds": 3600, "caseMetadataSeconds": 7200, "auditMetadataSeconds": 86400}
	return map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceRetentionPolicy", "metadata": map[string]any{"name": name, "namespace": permissionControl.Name, "uid": uid, "generation": 1, "resourceVersion": "opaque:retention"}, "spec": map[string]any{"scope": map[string]any{}, "purposeRef": "diagnostics", "defaults": durations, "maxima": durations, "rules": []any{}, "deletionBudgetSeconds": 300, "legalExceptions": "disabled"}, "status": map[string]any{"phase": "Ready", "generation": 999}}
}
func TestRetentionObservationPinsPolicyAndIgnoresStatus(t *testing.T) {
	object := retentionObject("baseline", "retention-uid")
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/evidenceretentionpolicies") {
			permissionReply(w, permissionList("EvidenceRetentionPolicy", "opaque:snapshot", "", object))
			return true
		}
		return false
	})
	c, err := NewRetentionClient(f.client, true)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := c.RetentionSnapshot(context.Background())
	if err != nil || len(snapshot.Policies) != 1 || !snapshot.Policies[0].Policy.Baseline {
		t.Fatal("complete baseline", err)
	}
	if snapshot.SourceClusterID != permissionCluster || snapshot.ControlNamespaceUID != permissionControl.UID || snapshot.FreshUntil.Sub(snapshot.ObservedAt) != 5*time.Second || snapshot.Policies[0].Policy.Revision.UID != "retention-uid" {
		t.Fatal("source identity lost")
	}
	object["status"] = map[string]any{"phase": "Anything", "observedGeneration": 123}
	object["metadata"].(map[string]any)["resourceVersion"] = "different"
	again, err := c.RetentionSnapshot(context.Background())
	if err != nil || again.Revision != snapshot.Revision {
		t.Fatal("status became authority", err)
	}
	object["spec"].(map[string]any)["deletionBudgetSeconds"] = 600
	changed, err := c.RetentionSnapshot(context.Background())
	if err != nil || changed.Revision.Digest == snapshot.Revision.Digest {
		t.Fatal("policy change missing from digest", err)
	}
	local, err := NewRetentionClient(f.client, false)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := local.RetentionSnapshot(context.Background())
	if err != nil || observed.Policies[0].Policy.Baseline {
		t.Fatal("local empty scope became hub baseline", err)
	}
}
func TestRetentionObservationRejectsMalformedPartialAndStaleSources(t *testing.T) {
	for _, mode := range []string{"unknown-field", "case-alias", "duplicate-json", "deleting-policy", "namespace-replaced", "invalid-selector", "impossible-budget", "page-mismatch", "forbidden", "expired"} {
		t.Run(mode, func(t *testing.T) {
			object := retentionObject("baseline", "retention-uid")
			switch mode {
			case "unknown-field":
				object["spec"].(map[string]any)["permissive"] = true
			case "case-alias":
				spec := object["spec"].(map[string]any)
				spec["PurposeRef"] = spec["purposeRef"]
				delete(spec, "purposeRef")
			case "deleting-policy":
				object["metadata"].(map[string]any)["deletionTimestamp"] = "2026-10-10T12:00:00Z"
			case "invalid-selector":
				object["spec"].(map[string]any)["scope"] = map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]string{"bad key": "value"}}}
			case "impossible-budget":
				object["spec"].(map[string]any)["deletionBudgetSeconds"] = 3600
			}
			var fixture permissionFixture
			namespaceReads := 0
			fixture = newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == "/api/v1/namespaces/asservat-system" && mode == "namespace-replaced" {
					namespaceReads++
					uid := permissionControl.UID
					if namespaceReads > 1 {
						uid = "replacement"
					}
					permissionReply(w, permissionNamespace(permissionControl.Name, uid))
					return true
				}
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
				if mode == "expired" {
					fixture.clock.Add(int64(6 * time.Second))
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
			c, err := NewRetentionClient(fixture.client, true)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot, err := c.RetentionSnapshot(context.Background()); err == nil || len(snapshot.Policies) != 0 {
				t.Fatal("unsafe source returned complete policy")
			}
		})
	}
}
