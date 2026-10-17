package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"k8s.io/client-go/rest"
)

func TestBoundedContextProtocol(t *testing.T) {
	pin := artifact.PinnedPod{Namespace: "synthetic", NamespaceUID: "ns-uid", Name: "app", UID: "pod-uid", NodeName: "node", ControllerUID: "rs-uid"}
	for _, mode := range []string{"safe-projection", "unowned-projection", "unexpected-owner", "redirect", "namespace-replaced", "controller-replaced", "oversized", "denied"} {
		t.Run(mode, func(t *testing.T) {
			selected := pin
			if mode == "unowned-projection" || mode == "unexpected-owner" {
				selected.ControllerUID = ""
			}
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if mode == "denied" {
					w.WriteHeader(403)
					w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403,"message":"MUST-NOT-LEAK"}`))
					return
				}
				if mode == "oversized" {
					w.Write([]byte(strings.Repeat(" ", (2<<20)+1)))
					return
				}
				if mode == "redirect" && r.URL.Path == "/api/v1/namespaces/synthetic" {
					http.Redirect(w, r, "/redirected", http.StatusFound)
					return
				}
				if r.URL.Path == "/api/v1/namespaces/synthetic" || r.URL.Path == "/redirected" {
					uid := "ns-uid"
					if mode == "namespace-replaced" {
						uid = "new-uid"
					}
					json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "synthetic", "uid": uid}})
					return
				}
				if r.URL.Path != "/api/v1/namespaces/synthetic/pods/app" {
					t.Errorf("unexpected API path %s", r.URL.Path)
					w.WriteHeader(404)
					return
				}
				owner := "rs-uid"
				if mode == "controller-replaced" {
					owner = "other-owner"
				}
				owners := []any{map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs", "uid": owner, "controller": true}}
				if mode == "unowned-projection" {
					owners = nil
				}
				json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "app", "namespace": "synthetic", "uid": "pod-uid", "resourceVersion": "123", "annotations": map[string]string{"sensitive": "MUST-NOT-LEAK"}, "ownerReferences": owners}, "spec": map[string]any{"nodeName": "node"}, "status": map[string]any{"phase": "MUST-NOT-LEAK", "message": "MUST-NOT-LEAK", "conditions": []any{map[string]any{"type": "Ready", "status": "True", "message": "MUST-NOT-LEAK"}}}})
			}))
			defer s.Close()
			config := &rest.Config{Host: s.URL, Transport: s.Client().Transport}
			c, err := NewContextClient(config)
			if err != nil {
				t.Fatal(err)
			}
			b, err := c.Capture(context.Background(), selected)
			if mode == "safe-projection" || mode == "unowned-projection" {
				if err != nil || strings.Contains(string(b), "MUST-NOT-LEAK") || !strings.Contains(string(b), `"phase":"Unknown"`) {
					t.Fatalf("projection: %v", err)
				}
				return
			}
			if err == nil || strings.Contains(err.Error(), "MUST-NOT-LEAK") || len(b) != 0 {
				t.Fatalf("unsafe error handling: %v", err)
			}
			if mode == "denied" && !errors.Is(err, ErrContextDenied) {
				t.Fatalf("denial not actionable: %v", err)
			}
		})
	}
}

func TestAPIContextCollectorDoesNotRequireNodeAssignment(t *testing.T) {
	for _, mode := range []string{"unscheduled", "scheduled", "replacement", "controller-changed", "node-pin"} {
		t.Run(mode, func(t *testing.T) {
			pin := artifact.PinnedPod{Namespace: "synthetic", NamespaceUID: "ns", Name: "app", UID: "pod", ControllerUID: "rs"}
			if mode == "node-pin" {
				pin.NodeName = "node"
			}
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method != "GET" {
					t.Error("context mutated the API")
				}
				switch r.URL.Path {
				case "/api/v1/namespaces/synthetic":
					json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "synthetic", "uid": "ns"}})
				case "/api/v1/namespaces/synthetic/pods/app":
					uid, owner, node, scheduled := "pod", "rs", "", "False"
					if mode == "scheduled" {
						node, scheduled = "newly-assigned", "True"
					}
					if mode == "replacement" {
						uid = "other"
					}
					if mode == "controller-changed" {
						owner = "other"
					}
					json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "app", "namespace": "synthetic", "uid": uid, "resourceVersion": "1", "ownerReferences": []any{map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "rs", "uid": owner, "controller": true}}}, "spec": map[string]any{"nodeName": node}, "status": map[string]any{"phase": "Pending", "message": "MUST-NOT-LEAK", "conditions": []any{map[string]any{"type": "PodScheduled", "status": scheduled}}}})
				default:
					t.Errorf("API context requested forbidden endpoint %s", r.URL.Path)
					w.WriteHeader(http.StatusForbidden)
				}
			}))
			defer s.Close()
			c, err := NewAPIContextClient(&rest.Config{Host: s.URL, Transport: s.Client().Transport})
			if err != nil {
				t.Fatal(err)
			}
			b, err := c.Capture(context.Background(), pin)
			if mode == "unscheduled" || mode == "scheduled" {
				if err != nil || !strings.Contains(string(b), `"phase":"Pending"`) || strings.Contains(string(b), "MUST-NOT-LEAK") || strings.Contains(string(b), "newly-assigned") {
					t.Fatal("unsafe or missing API projection", err)
				}
				return
			}
			if err == nil || len(b) != 0 {
				t.Fatal("changed Pod or mixed execution pin accepted")
			}
		})
	}
}
