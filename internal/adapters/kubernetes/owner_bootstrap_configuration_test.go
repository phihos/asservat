package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

func TestOwnerBootstrapProtectedSourceCapabilityAndDigest(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	root := base64.StdEncoding.EncodeToString(ownerConfigurationTestRoot(t, now))
	wire := map[string]any{"format": "asservat-hub-owner-configuration/v1", "installationID": ownerID(1), "clusterID": permissionCluster, "issuerEpoch": ownerID(2), "revision": 1, "suspended": false, "namespace": map[string]any{"name": permissionControl.Name, "uid": ownerID(3)}, "service": map[string]any{"name": "owner", "uid": ownerID(4)}, "deployment": map[string]any{"name": "hub", "uid": ownerID(5)}, "serviceAccount": map[string]any{"name": "hub", "uid": ownerID(6)}, "port": 9443, "nativePort": 9444, "issuerRoots": []string{root}}
	var payload atomic.Value
	store := func() {
		b, e := json.Marshal(wire)
		if e != nil {
			t.Fatal(e)
		}
		payload.Store(string(b))
	}
	store()
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/namespaces/" + permissionControl.Name:
			permissionReply(w, permissionNamespace(permissionControl.Name, ownerID(3)))
			return true
		case "/api/v1/namespaces/" + permissionControl.Name + "/configmaps/owner-pool":
			permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "owner-pool", "namespace": permissionControl.Name, "uid": ownerID(7), "resourceVersion": "1"}, "data": map[string]string{"owner-pool.json": payload.Load().(string)}})
			return true
		}
		return false
	})
	f.client.control.UID = ownerID(3)
	source := &OwnerConfigurationSource{client: f.client, name: "owner-pool", uid: ownerID(7), installation: ownerID(1)}
	legacy, _, e := source.snapshot(context.Background())
	if e != nil || legacy.Pool.NativeBootstrap != "" {
		t.Fatal("legacy source", e)
	}
	wire["nativeBootstrap"] = value.OwnerBootstrapProfile
	store()
	opted, _, e := source.snapshot(context.Background())
	if e != nil || opted.Pool.NativeBootstrap != value.OwnerBootstrapProfile || opted.Revision.Digest == legacy.Revision.Digest {
		t.Fatal("opted capability not part of original accepted source", e)
	}
	for _, mode := range []string{"unknown", "empty", "null", "missing-port"} {
		t.Run(mode, func(t *testing.T) {
			wire["nativeBootstrap"] = value.OwnerBootstrapProfile
			wire["nativePort"] = 9444
			switch mode {
			case "unknown":
				wire["nativeBootstrap"] = "other"
			case "empty":
				wire["nativeBootstrap"] = ""
			case "null":
				wire["nativeBootstrap"] = nil
			case "missing-port":
				delete(wire, "nativePort")
			}
			store()
			if _, _, e := source.snapshot(context.Background()); e == nil {
				t.Fatal("noncanonical or unsupported capability accepted")
			}
		})
	}
}
