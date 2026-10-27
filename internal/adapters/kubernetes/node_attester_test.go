package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

const (
	nodeInstallation = "10000000-0000-4000-8000-000000000001"
	nodeCluster      = "50000000-0000-4000-8000-000000000001"
	nodeBoot         = "22222222-2222-4222-8222-222222222222"
)

type nodeAPI struct {
	mu      sync.Mutex
	review  map[string]any
	pod     map[string]any
	ds      map[string]any
	node    map[string]any
	reviews int
}

func (f *nodeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out map[string]any
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews":
		b, _ := io.ReadAll(r.Body)
		var in struct{ Spec struct{ Audiences []string } }
		if json.Unmarshal(b, &in) != nil || len(in.Spec.Audiences) != 1 || in.Spec.Audiences[0] != contracts.NodeTokenAudience(nodeInstallation) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.reviews++
		out = f.review
	case r.URL.Path == "/api/v1/namespaces/collector/pods/collector-abc":
		out = f.pod
	case r.URL.Path == "/apis/apps/v1/namespaces/collector/daemonsets/asservat-node":
		out = f.ds
	case r.URL.Path == "/api/v1/nodes/worker-1":
		out = f.node
	}
	if out == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func goodNodeAPI() *nodeAPI {
	return &nodeAPI{
		review: map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "status": map[string]any{"authenticated": true, "audiences": []string{contracts.NodeTokenAudience(nodeInstallation)},
			"user": map[string]any{"username": "system:serviceaccount:collector:asservat-node", "uid": "sa-uid", "extra": map[string][]string{
				"authentication.kubernetes.io/pod-name": {"collector-abc"}, "authentication.kubernetes.io/pod-uid": {"pod-uid"},
				"authentication.kubernetes.io/node-name": {"worker-1"}, "authentication.kubernetes.io/node-uid": {"node-uid"}}}}},
		pod: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "collector-abc", "namespace": "collector", "uid": "pod-uid",
			"ownerReferences": []map[string]any{{"apiVersion": "apps/v1", "kind": "DaemonSet", "name": "asservat-node", "uid": "ds-uid", "controller": true}}},
			"spec": map[string]any{"nodeName": "worker-1", "serviceAccountName": "asservat-node"}, "status": map[string]any{"phase": "Running"}},
		ds:   map[string]any{"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": map[string]any{"name": "asservat-node", "namespace": "collector", "uid": "ds-uid"}},
		node: map[string]any{"apiVersion": "v1", "kind": "Node", "metadata": map[string]any{"name": "worker-1", "uid": "node-uid"}, "status": map[string]any{"nodeInfo": map[string]any{"bootID": nodeBoot, "containerRuntimeVersion": "containerd://2.1.3"}}},
	}
}

func set(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		m = m[p].(map[string]any)
	}
	if v == nil {
		delete(m, parts[len(parts)-1])
		return
	}
	m[parts[len(parts)-1]] = v
}

func nodeAttester(t *testing.T, api *nodeAPI) *NodeAttester {
	t.Helper()
	srv := httptest.NewTLSServer(api)
	t.Cleanup(srv.Close)
	c, err := NewPermissionClient(&rest.Config{Host: srv.URL, BearerToken: "connector", RateLimiter: flowcontrol.NewFakeAlwaysRateLimiter(), TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}},
		nodeCluster, cfg.NamespaceRef{Name: "collector", UID: "collector-ns-uid"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewNodeAttester(c, nodeInstallation, "asservat-node", "asservat-node")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestNodeAttesterBindsTokenPodDaemonSetAndBoot(t *testing.T) {
	api := goodNodeAPI()
	a := nodeAttester(t, api)
	id, err := a.AttestNode(context.Background(), []byte("header.payload.sig"), nodeBoot)
	if err != nil {
		t.Fatal(err)
	}
	if id.NodeName != "worker-1" || id.NodeUID != "node-uid" || id.PodName != "collector-abc" || id.PodUID != "pod-uid" || id.BootID != nodeBoot || id.Epoch != "" || id.Runtime != "containerd://2.1.3" {
		t.Fatalf("identity %+v", id)
	}
	cases := map[string]func(*nodeAPI){
		"unauthenticated": func(f *nodeAPI) { set(f.review, "status.authenticated", false) },
		"other audience":  func(f *nodeAPI) { set(f.review, "status.audiences", []string{"other"}) },
		"other account":   func(f *nodeAPI) { set(f.review, "status.user.username", "system:serviceaccount:collector:other") },
		"no node claims": func(f *nodeAPI) {
			delete(f.review["status"].(map[string]any)["user"].(map[string]any)["extra"].(map[string][]string), "authentication.kubernetes.io/node-uid")
		},
		"replaced pod":      func(f *nodeAPI) { set(f.pod, "metadata.uid", "other-pod") },
		"deleting pod":      func(f *nodeAPI) { set(f.pod, "metadata.deletionTimestamp", "2026-10-27T00:00:00Z") },
		"pending pod":       func(f *nodeAPI) { set(f.pod, "status.phase", "Pending") },
		"other node":        func(f *nodeAPI) { set(f.pod, "spec.nodeName", "worker-2") },
		"other pod account": func(f *nodeAPI) { set(f.pod, "spec.serviceAccountName", "default") },
		"not a daemonset": func(f *nodeAPI) {
			f.pod["metadata"].(map[string]any)["ownerReferences"].([]map[string]any)[0]["kind"] = "ReplicaSet"
		},
		"other daemonset": func(f *nodeAPI) {
			f.pod["metadata"].(map[string]any)["ownerReferences"].([]map[string]any)[0]["name"] = "other"
		},
		"replaced daemonset": func(f *nodeAPI) { set(f.ds, "metadata.uid", "new-ds-uid") },
		"daemonset gone":     func(f *nodeAPI) { f.ds = nil },
		"replaced node":      func(f *nodeAPI) { set(f.node, "metadata.uid", "new-node") },
		"rebooted node": func(f *nodeAPI) {
			set(f.node["status"].(map[string]any)["nodeInfo"].(map[string]any), "bootID", "33333333-3333-4333-8333-333333333333")
		},
		"case-folded node name": func(f *nodeAPI) { set(f.pod, "spec.nodeName", nil); set(f.pod, "spec.NodeName", "worker-1") },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			api := goodNodeAPI()
			edit(api)
			if _, err := nodeAttester(t, api).AttestNode(context.Background(), []byte("header.payload.sig"), nodeBoot); !errors.Is(err, delivery.ErrNodeDenied) {
				t.Fatalf("accepted or wrong error: %v", err)
			}
		})
	}
	if _, err := a.AttestNode(context.Background(), []byte("not a token!"), nodeBoot); !errors.Is(err, delivery.ErrNodeInvalid) {
		t.Fatal("invalid token syntax reached TokenReview")
	}
}
