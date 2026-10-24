package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// ADR-185: the catalog is closed, canonical and bounded to the profile's
// regional slots; membership itself grants nothing.
func TestClusterCatalogClosedSnapshot(t *testing.T) {
	const source = "11111111-1111-4111-8111-111111111114"
	empty := `{"format":"` + contracts.OwnerClusterCatalogFormat + `","clusters":[]}`
	slots := func(n int) string {
		raw, _ := json.Marshal(contracts.OwnerClusterCatalog{Format: contracts.OwnerClusterCatalogFormat, Clusters: make([]contracts.OwnerPublicCluster, n)})
		return string(raw)
	}
	for _, tc := range []struct{ name, raw string }{
		{"valid-empty", empty},
		{"unknown", strings.Replace(empty, `"clusters"`, `"admin":true,"clusters"`, 1)},
		{"null-clusters", strings.Replace(empty, `[]`, `null`, 1)},
		{"duplicate", strings.Replace(empty, `"clusters":[]`, `"clusters":[],"clusters":[]`, 1)},
		{"other-format", strings.Replace(empty, contracts.OwnerClusterCatalogFormat, "asservat-owner-cluster-catalog/v0", 1)},
		{"valid-full", slots(contracts.OwnerClusterCatalogSlots)},
		{"over-slots", slots(contracts.OwnerClusterCatalogSlots + 1)},
		{"trailing", empty + `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/cluster-catalog" {
					return false
				}
				permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "cluster-catalog", "namespace": permissionControl.Name, "uid": source, "resourceVersion": "opaque:1"}, "data": map[string]string{contracts.OwnerClusterCatalogFile: tc.raw}})
				return true
			})
			s := &ClusterCatalogSource{client: f.client, name: "cluster-catalog", uid: source}
			_, c, e := s.snapshot(context.Background())
			if !strings.HasPrefix(tc.name, "valid-") {
				if e == nil {
					t.Fatal("invalid catalog accepted")
				}
				return
			}
			if want := strings.Count(tc.raw, `"connector"`); e != nil || c.Clusters == nil || len(c.Clusters) != want {
				t.Fatal("valid catalog", e)
			}
		})
	}
}
