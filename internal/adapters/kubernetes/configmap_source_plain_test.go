package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Helm-native plan, slice 0: runtime sources are plain bounded ConfigMap GETs
// by the runtime's own client under ordinary RBAC. The loopback API here
// serves only GETs of the namespace and the named ConfigMaps; any admission
// policy, binding, review or dry-run request fails the test.
func plainSourceClients(t *testing.T, maps map[string]map[string]any) (*PermissionClient, *PermissionClient) {
	t.Helper()
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		prefix := "/api/v1/namespaces/" + permissionControl.Name + "/configmaps/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			return false
		}
		object, ok := maps[strings.TrimPrefix(r.URL.Path, prefix)]
		if !ok {
			return false
		}
		permissionReply(w, object)
		return true
	})
	probe, err := NewPermissionClient(f.config, permissionCluster, permissionControl, f.client.now)
	if err != nil {
		t.Fatal(err)
	}
	return f.client, probe
}

func plainSourceObject(name, uid string, immutable bool, data map[string]string) map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "immutable": immutable, "metadata": map[string]any{"name": name, "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "1"}, "data": data}
}

func plainSourcePlan(name string) cfg.ConfigMapAdministration {
	return cfg.ConfigMapAdministration{Name: name + "-guard", ControlNamespace: permissionControl, SourceName: name, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "admin"}}}
}

var plainSourcePin = GuardPin{PolicyUID: "policy", PolicyGeneration: 1, BindingUID: "binding", BindingResourceVersion: "1"}

func TestRuntimeSourcesArePlainReadsWithoutAdmissionGuards(t *testing.T) {
	const installation, catalogUID, workerUID, settingsUID = "11111111-1111-4111-8111-111111111112", "11111111-1111-4111-8111-111111111114", "11111111-1111-4111-8111-111111111113", "11111111-1111-4111-8111-111111111115"
	worker, _ := json.Marshal(map[string]any{
		"format": "asservat-worker-configuration/v1", "installationID": installation,
		"clusterID": permissionCluster, "recoveryEpoch": installation, "revision": 1, "suspended": false,
		"namespace":      map[string]any{"name": permissionControl.Name, "uid": permissionControl.UID},
		"serviceAccount": map[string]any{"name": "acquisition", "uid": "account-uid"},
		"priorityClass":  map[string]any{"name": "acquisition", "uid": "priority-uid"},
		"controlConfig":  map[string]any{"name": "worker-control", "uid": "control-uid", "sha256": strings.Repeat("1", 64)},
		"image":          "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), "imagePullSecrets": []string{},
		"cpuMillis": 100, "memoryBytes": 64 << 20, "maxRuntimeSeconds": 60,
	})
	observer, probe := plainSourceClients(t, map[string]map[string]any{
		"cluster-catalog": plainSourceObject("cluster-catalog", catalogUID, false, map[string]string{contracts.OwnerClusterCatalogFile: `{"format":"` + contracts.OwnerClusterCatalogFormat + `","clusters":[]}`}),
		"worker-profile":  plainSourceObject("worker-profile", workerUID, false, map[string]string{"worker-profile.json": string(worker)}),
	})

	t.Run("cluster-catalog", func(t *testing.T) {
		g, err := NewClusterCatalogProtection(observer, probe, plainSourcePlan("cluster-catalog"), plainSourcePin)
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewClusterCatalogSource(observer, g, "cluster-catalog", catalogUID)
		if err != nil {
			t.Fatal(err)
		}
		if c, err := s.ReadClusterCatalog(context.Background()); err != nil || c.Clusters == nil {
			t.Fatal("plain catalog read", err)
		}
	})
	t.Run("worker-configuration", func(t *testing.T) {
		g, err := NewWorkerConfigurationProtection(observer, probe, plainSourcePlan("worker-profile"), plainSourcePin)
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewWorkerConfigurationSource(observer, g, "worker-profile", workerUID, installation)
		if err != nil {
			t.Fatal(err)
		}
		start := observer.now()
		o, err := s.ReadWorkerConfiguration(context.Background())
		if err != nil || o.Configuration.ProtectionDigest != g.digest || !o.FreshUntil.Equal(start.Add(5*time.Second)) {
			t.Fatal("plain worker configuration read lost its digest or original window", err)
		}
	})
}

func TestFleetAndOwnerSourcesArePlainReadsWithoutAdmissionGuards(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	f.extraHandler = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/admissionregistration.k8s.io/") || strings.Contains(r.URL.Path, "/selfsubject") || r.Method != http.MethodGet {
			t.Error("plain source read used admission-guard machinery", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusForbidden)
			return true
		}
		return false
	}
	start := time.Now()
	a, err := f.source.fleet.FleetAdministration(context.Background())
	if err != nil || a.ObservedAt.Before(start) || a.FreshUntil.After(a.ObservedAt.Add(5*time.Second)) {
		t.Fatal("plain fleet read", err)
	}
	o, err := f.source.owner.ReadOwnerConfiguration(context.Background())
	if err != nil || o.Configuration.ProtectionDigest != f.source.owner.protection.digest {
		t.Fatal("plain owner read lost its configuration digest", err)
	}
	if f.probes.Load() != 0 || f.requests.Load() != 6 {
		t.Fatal("source reads changed their plain request graph", f.requests.Load())
	}
}
