package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// Parser tests use a synthetic API, not production admission/protection proof.
func TestWorkerConfigurationClosedSnapshot(t *testing.T) {
	const installation = "11111111-1111-4111-8111-111111111112"
	const source = "11111111-1111-4111-8111-111111111113"
	base := func() map[string]any {
		return map[string]any{
			"format": "asservat-worker-configuration/v1", "installationID": installation,
			"clusterID": permissionCluster, "recoveryEpoch": installation, "revision": 1, "suspended": false,
			"namespace":      map[string]any{"name": permissionControl.Name, "uid": permissionControl.UID},
			"serviceAccount": map[string]any{"name": "acquisition", "uid": "account-uid"},
			"priorityClass":  map[string]any{"name": "acquisition", "uid": "priority-uid"},
			"controlConfig":  map[string]any{"name": "worker-control", "uid": "control-uid", "sha256": strings.Repeat("1", 64)},
			"image":          "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), "imagePullSecrets": []string{},
			"cpuMillis": 100, "memoryBytes": 64 << 20, "maxRuntimeSeconds": 60,
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		raw    func(string) string
	}{
		{name: "valid"},
		{name: "unknown", mutate: func(v map[string]any) { v["command"] = []string{"sh"} }},
		{name: "missing-false", mutate: func(v map[string]any) { delete(v, "suspended") }},
		{name: "null-false", mutate: func(v map[string]any) { v["suspended"] = nil }},
		{name: "alias", mutate: func(v map[string]any) { v["Revision"] = v["revision"]; delete(v, "revision") }},
		{name: "duplicate", raw: func(s string) string { return strings.Replace(s, `"revision":1`, `"revision":1,"revision":1`, 1) }},
		{name: "trailing", raw: func(s string) string { return s + `{}` }},
		{name: "foreign-installation", mutate: func(v map[string]any) { v["installationID"] = permissionCluster }},
		{name: "foreign-cluster", mutate: func(v map[string]any) { v["clusterID"] = installation }},
		{name: "foreign-namespace", mutate: func(v map[string]any) { v["namespace"].(map[string]any)["uid"] = "replacement" }},
		{name: "missing-registry-list", mutate: func(v map[string]any) { delete(v, "imagePullSecrets") }},
		{name: "duplicate-registry", mutate: func(v map[string]any) { v["imagePullSecrets"] = []string{"pull", "pull"} }},
		{name: "invalid-account", mutate: func(v map[string]any) { v["serviceAccount"].(map[string]any)["name"] = "../account" }},
		{name: "unpinned-image", mutate: func(v map[string]any) { v["image"] = "synthetic.invalid/worker:latest" }},
		{name: "empty-digest", mutate: func(v map[string]any) { v["controlConfig"].(map[string]any)["sha256"] = strings.Repeat("0", 64) }},
		{name: "unbounded-runtime", mutate: func(v map[string]any) { v["maxRuntimeSeconds"] = 28801 }},
		{name: "unbounded-cpu", mutate: func(v map[string]any) { v["cpuMillis"] = 4001 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := base()
			if tc.mutate != nil {
				tc.mutate(v)
			}
			b, _ := json.Marshal(v)
			raw := string(b)
			if tc.raw != nil {
				raw = tc.raw(raw)
			}
			var payload atomic.Value
			payload.Store(raw)
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/worker-profile" {
					return false
				}
				permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "worker-profile", "namespace": permissionControl.Name, "uid": source, "resourceVersion": "opaque:1"}, "data": map[string]string{"worker-profile.json": payload.Load().(string)}})
				return true
			})
			s := &WorkerConfigurationSource{client: f.client, name: "worker-profile", uid: source, installation: installation}
			c, e := s.snapshot(context.Background())
			if tc.name != "valid" {
				if e == nil {
					t.Fatal("invalid worker configuration accepted")
				}
				return
			}
			if e != nil || !c.Profile.Valid() || c.Profile.Configuration.UID != source {
				t.Fatal("valid worker snapshot", e)
			}
			// ADR-204 decision 8: an installer-pinned copy of the document
			// derives the identical profile with the same parse; another
			// source UID is another profile, and another installation fails.
			var pinned contracts.WorkerConfiguration
			if json.Unmarshal(b, &pinned) != nil {
				t.Fatal("pinned document")
			}
			if copied, e := PinnedWorkerConfiguration(pinned, source, installation, permissionCluster); e != nil || copied != c {
				t.Fatal("pinned copy derived another profile", e)
			}
			if other, e := PinnedWorkerConfiguration(pinned, installation, installation, permissionCluster); e != nil || other.Profile == c.Profile {
				t.Fatal("pinned copy ignored its source", e)
			}
			if _, e := PinnedWorkerConfiguration(pinned, source, permissionCluster, permissionCluster); e == nil {
				t.Fatal("pinned copy of another installation accepted")
			}
			pretty, _ := json.MarshalIndent(v, "", "  ")
			payload.Store(string(pretty))
			again, e := s.snapshot(context.Background())
			if e != nil || again != c {
				t.Fatal("formatting changed canonical profile identity", e)
			}
		})
	}
}

// ADR-194 D1: only the exact installed marker reads as unconfigured; another
// installation's marker or a reformatted one is an invalid document.
func TestWorkerConfigurationUnconfiguredMarker(t *testing.T) {
	const installation = "11111111-1111-4111-8111-111111111112"
	const source = "11111111-1111-4111-8111-111111111113"
	for name, raw := range map[string]string{
		"exact":       contracts.UnconfiguredWorkerConfiguration(installation),
		"foreign":     contracts.UnconfiguredWorkerConfiguration(permissionCluster),
		"reformatted": strings.Replace(contracts.UnconfiguredWorkerConfiguration(installation), `,"`, `, "`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/worker-profile" {
					return false
				}
				permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "worker-profile", "namespace": permissionControl.Name, "uid": source, "resourceVersion": "opaque:1"}, "data": map[string]string{"worker-profile.json": raw}})
				return true
			})
			s := &WorkerConfigurationSource{client: f.client, name: "worker-profile", uid: source, installation: installation}
			_, e := s.snapshot(context.Background())
			if e == nil || errors.Is(e, ErrWorkerUnconfigured) != (name == "exact") {
				t.Fatal(name, e)
			}
		})
	}
}
