package kubernetes

import (
	"context"
	"maps"
	"net/url"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	networking "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// ADR-327: the public API may sit behind the operator's Ingress or Gateway.
// The installer creates the route in the protected hub namespace because only
// its runner and the installation administrators may write there.

var httpRouteResource = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}

// OwnerPublicRouteHost is the origin's host when a route can serve it: an
// https origin on the default port, since the hub-api requires Host to equal
// the origin's host exactly.
func OwnerPublicRouteHost(origin string) (string, bool) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Port() != "" || u.Hostname() == "" || len(validation.IsDNS1123Subdomain(u.Hostname())) != 0 {
		return "", false
	}
	return u.Hostname(), true
}

// ValidOwnerPublicRoute checks the closed route inputs of an exposure.
func ValidOwnerPublicRoute(e contracts.InstallerPublicExposure, origin string) bool {
	if e.TLS != "" && e.TLS != contracts.InstallerPublicTLSPod && e.TLS != contracts.InstallerPublicTLSProxy {
		return false
	}
	if e.Ingress == nil && e.HTTPRoute == nil {
		return true
	}
	if _, ok := OwnerPublicRouteHost(origin); !ok || e.Ingress != nil && e.HTTPRoute != nil {
		return false
	}
	if i := e.Ingress; i != nil {
		return (i.ClassName == "" || len(validation.IsDNS1123Subdomain(i.ClassName)) == 0) &&
			(i.TLSSecretName == "" || len(validation.IsDNS1123Subdomain(i.TLSSecretName)) == 0) && validRouteAnnotations(i.Annotations)
	}
	r := e.HTTPRoute
	if len(r.ParentRefs) == 0 || len(r.ParentRefs) > 8 || !validRouteAnnotations(r.Annotations) {
		return false
	}
	for _, p := range r.ParentRefs {
		if len(validation.IsDNS1123Subdomain(p.Name)) != 0 || p.Namespace != "" && len(validation.IsDNS1123Label(p.Namespace)) != 0 ||
			p.SectionName != "" && len(validation.IsDNS1123Subdomain(p.SectionName)) != 0 {
			return false
		}
	}
	return true
}

func validRouteAnnotations(a map[string]string) bool {
	if len(a) > 32 {
		return false
	}
	for k, v := range a {
		if len(validation.IsQualifiedName(k)) != 0 || len(v) > 4096 {
			return false
		}
	}
	return true
}

// EnsureOwnerPublicRoute creates the exposure's Ingress or HTTPRoute to the
// public Service, or accepts an existing one whose routing is unchanged.
func EnsureOwnerPublicRoute(ctx context.Context, config *rest.Config, namespace, installation string, e contracts.InstallerPublicExposure, origin string) error {
	host, ok := OwnerPublicRouteHost(origin)
	if ctx == nil || config == nil || namespace == "" || !authorization.UUID(installation) || !ok || !ValidOwnerPublicRoute(e, origin) {
		return cfg.ErrInvalid
	}
	name := OwnerPublicServiceName(installation)
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	if e.Ingress != nil {
		return ensureOwnerPublicIngress(call, config, namespace, name, host, *e.Ingress)
	}
	if e.HTTPRoute != nil {
		return ensureOwnerPublicHTTPRoute(call, config, namespace, name, host, *e.HTTPRoute)
	}
	return nil
}

func ownerPublicIngress(namespace, name, host string, in contracts.InstallerPublicIngress) *networking.Ingress {
	prefix := networking.PathTypePrefix
	i := &networking.Ingress{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace, Annotations: maps.Clone(in.Annotations)},
		Spec: networking.IngressSpec{Rules: []networking.IngressRule{{Host: host, IngressRuleValue: networking.IngressRuleValue{HTTP: &networking.HTTPIngressRuleValue{
			Paths: []networking.HTTPIngressPath{{Path: "/", PathType: &prefix, Backend: networking.IngressBackend{Service: &networking.IngressServiceBackend{
				Name: name, Port: networking.ServiceBackendPort{Number: contracts.OwnerInstalledPublicPort}}}}}}}}}}}
	if in.ClassName != "" {
		i.Spec.IngressClassName = &in.ClassName
	}
	if in.TLSSecretName != "" {
		i.Spec.TLS = []networking.IngressTLS{{Hosts: []string{host}, SecretName: in.TLSSecretName}}
	}
	return i
}

func ensureOwnerPublicIngress(ctx context.Context, config *rest.Config, namespace, name, host string, in contracts.InstallerPublicIngress) error {
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	want := ownerPublicIngress(namespace, name, host, in)
	ingresses := api.NetworkingV1().Ingresses(namespace)
	got, err := ingresses.Create(ctx, want, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		got, err = ingresses.Get(ctx, name, meta.GetOptions{})
	}
	if err != nil {
		return cfg.ErrUnavailable
	}
	if !equalJSON(got.Spec, want.Spec) || !annotationsKept(got.Annotations, want.Annotations) {
		return cfg.ErrChanged
	}
	return nil
}

func ownerPublicHTTPRoute(namespace, name, host string, in contracts.InstallerPublicHTTPRoute) *unstructured.Unstructured {
	parents := make([]any, 0, len(in.ParentRefs))
	for _, p := range in.ParentRefs {
		ref := map[string]any{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": p.Name}
		if p.Namespace != "" {
			ref["namespace"] = p.Namespace
		}
		if p.SectionName != "" {
			ref["sectionName"] = p.SectionName
		}
		parents = append(parents, ref)
	}
	annotations := map[string]any{}
	for k, v := range in.Annotations {
		annotations[k] = v
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]any{"name": name, "namespace": namespace, "annotations": annotations},
		"spec": map[string]any{
			"parentRefs": parents, "hostnames": []any{host},
			"rules": []any{map[string]any{
				"matches":     []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/"}}},
				"backendRefs": []any{map[string]any{"group": "", "kind": "Service", "name": name, "port": int64(contracts.OwnerInstalledPublicPort), "weight": int64(1)}},
			}},
		},
	}}
}

func ensureOwnerPublicHTTPRoute(ctx context.Context, config *rest.Config, namespace, name, host string, in contracts.InstallerPublicHTTPRoute) error {
	api, err := dynamic.NewForConfig(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	want := ownerPublicHTTPRoute(namespace, name, host, in)
	routes := api.Resource(httpRouteResource).Namespace(namespace)
	got, err := routes.Create(ctx, want, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		got, err = routes.Get(ctx, name, meta.GetOptions{})
	}
	if err != nil {
		return cfg.ErrUnavailable
	}
	if !sameHTTPRouteRouting(got, want) || !annotationsKept(got.GetAnnotations(), in.Annotations) {
		return cfg.ErrChanged
	}
	return nil
}

// sameHTTPRouteRouting compares the fields Asservat sets; the API server may
// add defaults (for example match headers or timeouts) that do not reroute.
func sameHTTPRouteRouting(got, want *unstructured.Unstructured) bool {
	for _, field := range [][]string{{"spec", "parentRefs"}, {"spec", "hostnames"}} {
		g, _, _ := unstructured.NestedFieldNoCopy(got.Object, field...)
		w, _, _ := unstructured.NestedFieldNoCopy(want.Object, field...)
		if !equalJSON(g, w) {
			return false
		}
	}
	rules, _, _ := unstructured.NestedSlice(got.Object, "spec", "rules")
	wantRules, _, _ := unstructured.NestedSlice(want.Object, "spec", "rules")
	if len(rules) != 1 || len(wantRules) != 1 {
		return false
	}
	g, _ := rules[0].(map[string]any)
	w, _ := wantRules[0].(map[string]any)
	return equalJSON(g["backendRefs"], w["backendRefs"]) && equalJSON(g["matches"], w["matches"])
}

// annotationsKept reports whether every configured annotation is present
// unchanged; controllers may add their own.
func annotationsKept(got, want map[string]string) bool {
	for k, w := range want {
		if v, ok := got[k]; !ok || v != w {
			return false
		}
	}
	return true
}
