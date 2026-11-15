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
	nodeCluster = "50000000-0000-4000-8000-000000000001"
	nodeBoot    = "22222222-2222-4222-8222-222222222222"
)

type nodeAPI struct {
	mu      sync.Mutex
	review  map[string]any
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
		if json.Unmarshal(b, &in) != nil || len(in.Spec.Audiences) != 1 || in.Spec.Audiences[0] != contracts.NodeTokenAudience {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.reviews++
		out = f.review
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
		review: map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "status": map[string]any{"authenticated": true, "audiences": []string{contracts.NodeTokenAudience},
			"user": map[string]any{"username": "system:serviceaccount:collector:asservat-node", "uid": "sa-uid", "extra": map[string][]string{
				"authentication.kubernetes.io/pod-name": {"collector-abc"}, "authentication.kubernetes.io/pod-uid": {"pod-uid"},
				"authentication.kubernetes.io/node-name": {"worker-1"}, "authentication.kubernetes.io/node-uid": {"node-uid"}}}}},
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
	a, err := NewNodeAttester(c, "asservat-node")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestNodeAttesterReviewsTokenAndReadsNode(t *testing.T) {
	api := goodNodeAPI()
	a := nodeAttester(t, api)
	id, err := a.AttestNode(context.Background(), []byte("header.payload.sig"))
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
		"replaced node": func(f *nodeAPI) { set(f.node, "metadata.uid", "new-node") },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			api := goodNodeAPI()
			edit(api)
			if _, err := nodeAttester(t, api).AttestNode(context.Background(), []byte("header.payload.sig")); !errors.Is(err, delivery.ErrNodeDenied) {
				t.Fatalf("accepted or wrong error: %v", err)
			}
		})
	}
	if _, err := a.AttestNode(context.Background(), []byte("not a token!")); !errors.Is(err, delivery.ErrNodeInvalid) {
		t.Fatal("invalid token syntax reached TokenReview")
	}
}
