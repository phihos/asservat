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
	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// routeAPI is a minimal API server that stores one object of each route kind.
func routeAPI(t *testing.T) (*rest.Config, map[string]map[string]any) {
	stored := map[string]map[string]any{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		kind := ""
		switch {
		case strings.Contains(r.URL.Path, "/apis/networking.k8s.io/v1/namespaces/hub/ingresses"):
			kind = "Ingress"
		case strings.Contains(r.URL.Path, "/apis/gateway.networking.k8s.io/v1/namespaces/hub/httproutes"):
			kind = "HTTPRoute"
		default:
			w.WriteHeader(404)
			return
		}
		if r.Method == http.MethodPost {
			if stored[kind] != nil {
				w.WriteHeader(409)
				_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: meta.StatusReasonAlreadyExists, Code: 409})
				return
			}
			object := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&object)
			stored[kind] = object
		}
		if stored[kind] == nil {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(stored[kind])
	}))
	t.Cleanup(server.Close)
	return &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, stored
}

func TestOwnerPublicIngressCreateAndExactReopen(t *testing.T) {
	config, stored := routeAPI(t)
	e := contracts.InstallerPublicExposure{ServiceType: "ClusterIP", TLS: contracts.InstallerPublicTLSProxy, Ingress: &contracts.InstallerPublicIngress{ClassName: "example-class", Annotations: map[string]string{"example.com/timeout": "1h"}}}
	if err := EnsureOwnerPublicRoute(context.Background(), config, "hub", ownerID(1), e, "https://asservat.example"); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(stored["Ingress"])
	var got networking.Ingress
	_ = json.Unmarshal(raw, &got)
	rule := got.Spec.Rules[0]
	backend := rule.HTTP.Paths[0].Backend.Service
	if got.Name != OwnerPublicServiceName(ownerID(1)) || *got.Spec.IngressClassName != "example-class" || rule.Host != "asservat.example" || rule.HTTP.Paths[0].Path != "/" ||
		backend.Name != OwnerPublicServiceName(ownerID(1)) || backend.Port.Number != contracts.OwnerInstalledPublicPort || len(got.Spec.TLS) != 0 || got.Annotations["example.com/timeout"] != "1h" {
		t.Fatal("owner public ingress", string(raw))
	}
	if err := EnsureOwnerPublicRoute(context.Background(), config, "hub", ownerID(1), e, "https://asservat.example"); err != nil {
		t.Fatal("exact rerun refused", err)
	}
	stored["Ingress"]["metadata"].(map[string]any)["annotations"].(map[string]any)["controller.example/added"] = "kept"
	if err := EnsureOwnerPublicRoute(context.Background(), config, "hub", ownerID(1), e, "https://asservat.example"); err != nil {
		t.Fatal("controller annotation refused", err)
	}
	// An admission-defaulted class on an unclassed Ingress is not a change.
	unclassed := contracts.InstallerPublicExposure{ServiceType: "ClusterIP", TLS: contracts.InstallerPublicTLSProxy, Ingress: &contracts.InstallerPublicIngress{Annotations: e.Ingress.Annotations}}
	if err := EnsureOwnerPublicRoute(context.Background(), config, "hub", ownerID(1), unclassed, "https://asservat.example"); err != nil {
		t.Fatal("defaulted ingress class refused", err)
	}
	if err := EnsureOwnerPublicRoute(context.Background(), config, "hub", ownerID(1), e, "https://other.example"); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("changed host accepted", err)
	}
	e.Ingress.Annotations["example.com/timeout"] = "2h"
	if err := EnsureOwnerPublicRoute(context.Background(), config, "hub", ownerID(1), e, "https://asservat.example"); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("changed annotation accepted", err)
	}
}

func TestOwnerPublicHTTPRouteCreateAndExactReopen(t *testing.T) {
	config, stored := routeAPI(t)
	e := contracts.InstallerPublicExposure{ServiceType: "ClusterIP", TLS: contracts.InstallerPublicTLSProxy, HTTPRoute: &contracts.InstallerPublicHTTPRoute{ParentRefs: []contracts.InstallerGatewayParent{{Name: "edge", Namespace: "gateways", SectionName: "https"}}}}
	if err := EnsureOwnerPublicRoute(context.Background(), config, "hub", ownerID(1), e, "https://asservat.example"); err != nil {
		t.Fatal(err)
	}
	spec := stored["HTTPRoute"]["spec"].(map[string]any)
	parent := spec["parentRefs"].([]any)[0].(map[string]any)
	backend := spec["rules"].([]any)[0].(map[string]any)["backendRefs"].([]any)[0].(map[string]any)
	if parent["name"] != "edge" || parent["namespace"] != "gateways" || parent["sectionName"] != "https" || parent["kind"] != "Gateway" ||
		spec["hostnames"].([]any)[0] != "asservat.example" || backend["name"] != OwnerPublicServiceName(ownerID(1)) || backend["port"] != float64(contracts.OwnerInstalledPublicPort) {
		t.Fatal("owner public route", stored["HTTPRoute"])
	}
	// API defaults on the stored rule (here a timeout) do not reroute.
	spec["rules"].([]any)[0].(map[string]any)["timeouts"] = map[string]any{"request": "0s"}
	if err := EnsureOwnerPublicRoute(context.Background(), config, "hub", ownerID(1), e, "https://asservat.example"); err != nil {
		t.Fatal("exact rerun refused", err)
	}
	e.HTTPRoute.ParentRefs[0].Name = "other"
	if err := EnsureOwnerPublicRoute(context.Background(), config, "hub", ownerID(1), e, "https://asservat.example"); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("changed parent accepted", err)
	}
}

func TestValidOwnerPublicRoute(t *testing.T) {
	ingress := &contracts.InstallerPublicIngress{ClassName: "nginx"}
	route := &contracts.InstallerPublicHTTPRoute{ParentRefs: []contracts.InstallerGatewayParent{{Name: "edge"}}}
	for _, tc := range []struct {
		name   string
		e      contracts.InstallerPublicExposure
		origin string
		want   bool
	}{
		{"plain service", contracts.InstallerPublicExposure{ServiceType: "NodePort"}, "https://a.example:31450", true},
		{"proxy tls", contracts.InstallerPublicExposure{ServiceType: "ClusterIP", TLS: "proxy", Ingress: ingress}, "https://a.example", true},
		{"pod tls behind route", contracts.InstallerPublicExposure{ServiceType: "ClusterIP", TLS: "pod", HTTPRoute: route}, "https://a.example", true},
		{"unknown tls", contracts.InstallerPublicExposure{ServiceType: "ClusterIP", TLS: "edge"}, "https://a.example", false},
		{"route with origin port", contracts.InstallerPublicExposure{ServiceType: "ClusterIP", Ingress: ingress}, "https://a.example:8443", false},
		{"both routes", contracts.InstallerPublicExposure{ServiceType: "ClusterIP", Ingress: ingress, HTTPRoute: route}, "https://a.example", false},
		{"bad class", contracts.InstallerPublicExposure{ServiceType: "ClusterIP", Ingress: &contracts.InstallerPublicIngress{ClassName: "Bad_Class"}}, "https://a.example", false},
		{"bad annotation", contracts.InstallerPublicExposure{ServiceType: "ClusterIP", Ingress: &contracts.InstallerPublicIngress{Annotations: map[string]string{"bad key": "x"}}}, "https://a.example", false},
		{"proxy tls on a node port", contracts.InstallerPublicExposure{ServiceType: "NodePort", TLS: "proxy"}, "https://a.example", false},
		{"route to a load balancer", contracts.InstallerPublicExposure{ServiceType: "LoadBalancer", Ingress: ingress}, "https://a.example", false},
		{"proxy tls behind an external route", contracts.InstallerPublicExposure{ServiceType: "ClusterIP", TLS: "proxy"}, "https://a.example", true},
		{"no parents", contracts.InstallerPublicExposure{ServiceType: "ClusterIP", HTTPRoute: &contracts.InstallerPublicHTTPRoute{}}, "https://a.example", false},
		{"bad parent namespace", contracts.InstallerPublicExposure{ServiceType: "ClusterIP", HTTPRoute: &contracts.InstallerPublicHTTPRoute{ParentRefs: []contracts.InstallerGatewayParent{{Name: "edge", Namespace: "Not.A.Label"}}}}, "https://a.example", false},
	} {
		if got := ValidOwnerPublicRoute(tc.e, tc.origin); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
