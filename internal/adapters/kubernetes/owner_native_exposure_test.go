package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// ADR-196 decision 5: the owner's native L4 Service selects exactly the owner
// Deployment's Pods; a rerun accepts it unchanged and refuses a changed one.
func TestOwnerNativeServiceCreateAndExactReopen(t *testing.T) {
	var stored *core.Service
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/deployments/owner"):
			_ = json.NewEncoder(w).Encode(apps.Deployment{TypeMeta: meta.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}, Spec: apps.DeploymentSpec{Selector: &meta.LabelSelector{MatchLabels: map[string]string{"app": "owner"}}}})
		case strings.Contains(r.URL.Path, "/services"):
			if r.Method == http.MethodPost {
				if stored != nil {
					w.WriteHeader(409)
					_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: meta.StatusReasonAlreadyExists, Code: 409})
					return
				}
				stored = &core.Service{}
				_ = json.NewDecoder(r.Body).Decode(stored)
				stored.TypeMeta = meta.TypeMeta{Kind: "Service", APIVersion: "v1"}
			}
			_ = json.NewEncoder(w).Encode(stored)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	if err := EnsureOwnerNativeService(context.Background(), config, "hub", ownerID(1), "owner", "NodePort", 31447, 31448); err != nil {
		t.Fatal(err)
	}
	p, o := stored.Spec.Ports[0], stored.Spec.Ports[1]
	if stored.Name != OwnerNativeServiceName(ownerID(1)) || stored.Spec.Selector["app"] != "owner" || p.Port != contracts.OwnerInstalledNativePort || p.NodePort != 31447 ||
		o.Name != "operation" || o.Port != contracts.OwnerInstalledOperationPort || o.TargetPort.IntVal != contracts.OwnerInstalledOperationPort || o.NodePort != 31448 {
		t.Fatal("owner native service", stored.Spec)
	}
	if err := EnsureOwnerNativeService(context.Background(), config, "hub", ownerID(1), "owner", "NodePort", 31447, 31448); err != nil {
		t.Fatal("exact rerun refused", err)
	}
	stored.Spec.Ports[1].NodePort = 31449
	if err := EnsureOwnerNativeService(context.Background(), config, "hub", ownerID(1), "owner", "NodePort", 31447, 31448); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("changed operation node port accepted", err)
	}
	stored.Spec.Ports[1].NodePort = 31448
	if err := EnsureOwnerNativeService(context.Background(), config, "hub", ownerID(1), "owner", "NodePort", 31447, 31447); !errors.Is(err, cfg.ErrInvalid) {
		t.Fatal("shared node port accepted", err)
	}
	stored.Spec.Selector = map[string]string{"app": "other"}
	if err := EnsureOwnerNativeService(context.Background(), config, "hub", ownerID(1), "owner", "NodePort", 31447, 31448); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("changed service accepted", err)
	}
	if err := EnsureOwnerNativeService(context.Background(), config, "hub", ownerID(1), "owner", "ClusterIP", 0, 0); !errors.Is(err, cfg.ErrInvalid) {
		t.Fatal("internal-only service type accepted", err)
	}
}

// ADR-202: the public API's own L4 Service on the public port; an exact rerun
// is accepted and a changed node port or selector is refused.
func TestOwnerPublicServiceCreateAndExactReopen(t *testing.T) {
	var stored *core.Service
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/deployments/owner"):
			_ = json.NewEncoder(w).Encode(apps.Deployment{TypeMeta: meta.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}, Spec: apps.DeploymentSpec{Selector: &meta.LabelSelector{MatchLabels: map[string]string{"app": "owner"}}}})
		case strings.Contains(r.URL.Path, "/services"):
			if r.Method == http.MethodPost {
				if stored != nil {
					w.WriteHeader(409)
					_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: meta.StatusReasonAlreadyExists, Code: 409})
					return
				}
				stored = &core.Service{}
				_ = json.NewDecoder(r.Body).Decode(stored)
				stored.TypeMeta = meta.TypeMeta{Kind: "Service", APIVersion: "v1"}
			}
			_ = json.NewEncoder(w).Encode(stored)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	if err := EnsureOwnerPublicService(context.Background(), config, "hub", ownerID(1), "owner", "NodePort", 31450); err != nil {
		t.Fatal(err)
	}
	p := stored.Spec.Ports[0]
	if stored.Name != OwnerPublicServiceName(ownerID(1)) || stored.Spec.Selector["app"] != "owner" || len(stored.Spec.Ports) != 1 || p.Name != "public" || p.Port != contracts.OwnerInstalledPublicPort || p.TargetPort.IntVal != contracts.OwnerInstalledPublicPort || p.NodePort != 31450 {
		t.Fatal("owner public service", stored.Spec)
	}
	if err := EnsureOwnerPublicService(context.Background(), config, "hub", ownerID(1), "owner", "NodePort", 31450); err != nil {
		t.Fatal("exact rerun refused", err)
	}
	if err := EnsureOwnerPublicService(context.Background(), config, "hub", ownerID(1), "owner", "LoadBalancer", 31450); !errors.Is(err, cfg.ErrInvalid) {
		t.Fatal("node port with a load balancer accepted", err)
	}
	stored.Spec.Ports[0].NodePort = 31451
	if err := EnsureOwnerPublicService(context.Background(), config, "hub", ownerID(1), "owner", "NodePort", 31450); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("changed node port accepted", err)
	}
	stored.Spec.Ports[0].NodePort = 31450
	stored.Spec.Selector = map[string]string{"app": "other"}
	if err := EnsureOwnerPublicService(context.Background(), config, "hub", ownerID(1), "owner", "NodePort", 31450); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("changed selector accepted", err)
	}
}
