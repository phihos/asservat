package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

const (
	workerTestInstallation = "11111111-1111-4111-8111-111111111112"
	workerTestSource       = "11111111-1111-4111-8111-111111111113"
	workerTestEpoch        = "11111111-1111-4111-8111-111111111119"
	workerTestAccount      = "22222222-2222-4222-8222-222222222221"
	workerTestPriority     = "22222222-2222-4222-8222-222222222222"
	workerTestControl      = "22222222-2222-4222-8222-222222222223"
	workerTestStore        = "22222222-2222-4222-8222-222222222224"
)

// workerTestDocument is the Helm-rendered v3 profile (download-worker.yaml).
func workerTestDocument() map[string]any {
	return map[string]any{
		"format": contracts.WorkerConfigurationFormat, "revision": 1, "suspended": false,
		"namespace": permissionControl.Name, "serviceAccount": "acquisition", "priorityClass": "acquisition", "controlConfig": "worker-control",
		"image": "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), "imagePullSecrets": []string{},
		"cpuMillis": 100, "memoryBytes": 64 << 20, "maxRuntimeSeconds": 60, "storeCredentials": "worker-store",
	}
}

// workerTestFixture serves the profile ConfigMap and the objects it names;
// every request is a plain GET by name.
func workerTestFixture(t *testing.T, payload *atomic.Value, requests *atomic.Int64) permissionFixture {
	t.Helper()
	ns := "/api/v1/namespaces/" + permissionControl.Name
	objects := map[string]map[string]any{
		ns + "/serviceaccounts/acquisition":                      {"metadata": map[string]any{"name": "acquisition", "uid": workerTestAccount}},
		"/apis/scheduling.k8s.io/v1/priorityclasses/acquisition": {"metadata": map[string]any{"name": "acquisition", "uid": workerTestPriority}},
		ns + "/configmaps/worker-control":                        {"metadata": map[string]any{"name": "worker-control", "uid": workerTestControl}},
		ns + "/secrets/worker-store":                             {"metadata": map[string]any{"name": "worker-store", "uid": workerTestStore}},
	}
	return newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet {
			return false
		}
		if requests != nil {
			requests.Add(1)
		}
		if r.URL.Path == ns+"/configmaps/worker-profile" {
			permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "worker-profile", "namespace": permissionControl.Name, "uid": workerTestSource, "resourceVersion": "1"}, "data": map[string]string{"worker-profile.json": payload.Load().(string)}})
			return true
		}
		if o, ok := objects[r.URL.Path]; ok {
			permissionReply(w, o)
			return true
		}
		if strings.HasPrefix(r.URL.Path, ns+"/") || strings.HasPrefix(r.URL.Path, "/apis/scheduling.k8s.io/") {
			http.NotFound(w, r)
			return true
		}
		return false
	})
}

func workerTestSourceFor(t *testing.T, f permissionFixture) *WorkerConfigurationSource {
	t.Helper()
	g, err := NewPlainWorkerConfigurationProtection(f.client, "worker-profile")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWorkerConfigurationSource(f.client, g, "worker-profile", workerTestSource, workerTestInstallation, workerTestEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The v3 document holds names only: the reader fills the caller's IDs, the
// client's namespace UID and each named object's UID read by name.
func TestWorkerConfigurationV3FillsIDsAndUIDs(t *testing.T) {
	b, _ := json.Marshal(workerTestDocument())
	var payload atomic.Value
	payload.Store(string(b))
	var requests atomic.Int64
	f := workerTestFixture(t, &payload, &requests)
	s := workerTestSourceFor(t, f)
	start := f.client.now()
	o, err := s.ReadWorkerConfiguration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, p := o.Configuration, o.Configuration.Profile
	if c.RecoveryEpoch != workerTestEpoch || c.Suspended || c.ProtectionDigest != s.protection.digest || !o.FreshUntil.Equal(start.Add(5*time.Second)) {
		t.Fatal("configuration", c)
	}
	if p.InstallationID != workerTestInstallation || p.ClusterID != permissionCluster || p.Namespace != permissionControl.Name || p.NamespaceUID != permissionControl.UID || p.Configuration.UID != workerTestSource || p.Configuration.Generation != 1 {
		t.Fatal("generated IDs", p)
	}
	if p.ServiceAccountUID != workerTestAccount || p.PriorityClassUID != workerTestPriority || p.ControlConfigUID != workerTestControl || p.StoreCredentialSecret != "worker-store" || p.StoreCredentialSecretUID != workerTestStore {
		t.Fatal("object UIDs", p)
	}
	// Namespace, profile, namespace (bracketed read), then account,
	// PriorityClass, control and store by name.
	if requests.Load() != 7 {
		t.Fatal("request graph", requests.Load())
	}
	// The key service's one-shot read derives the identical profile.
	profile, err := ReadWorkerProfile(context.Background(), f.client, "worker-profile", workerTestInstallation, workerTestEpoch)
	if err != nil || profile != p {
		t.Fatal("ReadWorkerProfile derived another profile", err)
	}
	// Formatting does not change the revision digest.
	pretty, _ := json.MarshalIndent(workerTestDocument(), "", "  ")
	payload.Store(string(pretty))
	again, err := s.ReadWorkerConfiguration(context.Background())
	if err != nil || again.Configuration.Profile != p {
		t.Fatal("formatting changed profile identity", err)
	}
	// Without a store Secret the worker has no native transfer.
	v := workerTestDocument()
	delete(v, "storeCredentials")
	b, _ = json.Marshal(v)
	payload.Store(string(b))
	plain, err := s.ReadWorkerConfiguration(context.Background())
	if err != nil || plain.Configuration.Profile.StoreCredentialSecret != "" || plain.Configuration.Profile.StoreCredentialSecretUID != "" {
		t.Fatal("profile without store", err)
	}
}

func TestWorkerConfigurationV3RejectsInvalidDocuments(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		raw    func(string) string
	}{
		{name: "unknown", mutate: func(v map[string]any) { v["command"] = []string{"sh"} }},
		{name: "generated-id", mutate: func(v map[string]any) { v["installationID"] = workerTestInstallation }},
		{name: "old-format", mutate: func(v map[string]any) { v["format"] = "asservat-worker-configuration/v2" }},
		{name: "trailing", raw: func(s string) string { return s + `{}` }},
		{name: "foreign-namespace", mutate: func(v map[string]any) { v["namespace"] = "other" }},
		{name: "missing-registry-list", mutate: func(v map[string]any) { delete(v, "imagePullSecrets") }},
		{name: "duplicate-registry", mutate: func(v map[string]any) { v["imagePullSecrets"] = []string{"pull", "pull"} }},
		{name: "invalid-account", mutate: func(v map[string]any) { v["serviceAccount"] = "../account" }},
		{name: "unknown-control", mutate: func(v map[string]any) { v["controlConfig"] = "other-control" }},
		{name: "unknown-store", mutate: func(v map[string]any) { v["storeCredentials"] = "other-store" }},
		{name: "unpinned-image", mutate: func(v map[string]any) { v["image"] = "synthetic.invalid/worker:latest" }},
		{name: "unbounded-runtime", mutate: func(v map[string]any) { v["maxRuntimeSeconds"] = 28801 }},
		{name: "unbounded-cpu", mutate: func(v map[string]any) { v["cpuMillis"] = 4001 }},
		{name: "zero-revision", mutate: func(v map[string]any) { v["revision"] = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := workerTestDocument()
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
			s := workerTestSourceFor(t, workerTestFixture(t, &payload, nil))
			if _, err := s.ReadWorkerConfiguration(context.Background()); err == nil {
				t.Fatal("invalid worker configuration accepted")
			}
		})
	}
}
