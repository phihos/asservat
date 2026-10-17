package integration

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

func testPolicySourceObservation(t *testing.T, ctx context.Context, config *rest.Config, cluster string, control, ns cfg.NamespaceRef, token, dsn, root, installation string) {
	t.Helper()
	admin, e := dynamic.NewForConfig(config)
	if e != nil {
		t.Fatal(e)
	}
	native, e := kubernetes.NewForConfig(config)
	if e != nil {
		t.Fatal(e)
	}
	crds := admin.Resource(schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"})
	// Fixture-only permissive schema: the product reader must reject invalid
	// authored content itself. This is deliberately not a shipping DebugPolicy CRD.
	crd := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "metadata": map[string]any{"name": "debugpolicies.asservat.io"}, "spec": map[string]any{"group": "asservat.io", "scope": "Namespaced", "names": map[string]any{"plural": "debugpolicies", "singular": "debugpolicy", "kind": "DebugPolicy"}, "versions": []any{map[string]any{"name": "v1alpha1", "served": true, "storage": true, "subresources": map[string]any{"status": map[string]any{}}, "schema": map[string]any{"openAPIV3Schema": map[string]any{"type": "object", "x-kubernetes-preserve-unknown-fields": true}}}}}}}
	if _, e := crds.Create(ctx, crd, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		live, e := crds.Get(ctx, "debugpolicies.asservat.io", meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		conditions, _, _ := unstructured.NestedSlice(live.Object, "status", "conditions")
		ready := false
		for _, v := range conditions {
			c := v.(map[string]any)
			if c["type"] == "Established" && c["status"] == "True" {
				ready = true
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned policy CRD not established")
		}
		time.Sleep(25 * time.Millisecond)
	}
	data, e := os.ReadFile("../../examples/policy-deployment.yaml")
	if e != nil {
		t.Fatal(e)
	}
	data, e = yaml.YAMLToJSON(data)
	if e != nil {
		t.Fatal(e)
	}
	o := &unstructured.Unstructured{}
	if e := json.Unmarshal(data, &o.Object); e != nil {
		t.Fatal(e)
	}
	o.SetNamespace(ns.Name)
	gr := schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "debugpolicies"}
	policies := admin.Resource(gr).Namespace(ns.Name)
	o, e = policies.Create(ctx, o, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	limited := &rest.Config{Host: config.Host, BearerToken: token, TLSClientConfig: rest.TLSClientConfig{CAData: config.CAData, CAFile: config.CAFile, ServerName: config.ServerName}}
	client, e := kube.NewPermissionClient(limited, cluster, control, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	reader, e := kube.NewPolicySourceClient(client, installation, ns, o.GetName(), string(o.GetUID()))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := reader.PolicySource(ctx); e == nil {
		t.Fatal("policy source read without explicit RBAC")
	}
	_, e = native.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "policy-source-reader"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"asservat.io"}, Resources: []string{"debugpolicies"}, ResourceNames: []string{o.GetName()}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	_, e = native.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "policy-source-reader"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "permission-reader", Namespace: control.Name}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "policy-source-reader"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	restricted, e := dynamic.NewForConfig(limited)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := restricted.Resource(gr).Namespace(ns.Name).Patch(ctx, o.GetName(), types.MergePatchType, []byte(`{"spec":{"suspended":true}}`), meta.PatchOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("source reader can change policy")
	}
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
	pc, e := pgxpool.ParseConfig("postgres://policy_source_runtime:synthetic-policy-source@" + address + "/custody_test?sslmode=disable")
	if e != nil {
		t.Fatal(e)
	}
	pc.ConnConfig.TLSConfig = tlsConfig
	pc.ConnConfig.Fallbacks = nil
	pc.MaxConns = 2
	pool, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	store, e := postgres.NewPolicies(ctx, pool, root, installation)
	if e != nil {
		t.Fatal(e)
	}
	observer := app.PolicySourceObserver{Source: reader, Writer: store, Now: time.Now}
	check := func(want int64, deleted bool) {
		t.Helper()
		if e := observer.Reconcile(ctx); e != nil {
			t.Fatal(e)
		}
		var version int64
		var got bool
		if e := pool.QueryRow(ctx, "SELECT intent_version,deleted FROM policy_source WHERE root_id=$1 AND policy_uid=$2", root, string(o.GetUID())).Scan(&version, &got); e != nil || version != want || got != deleted {
			t.Fatalf("source projection: version=%d deleted=%v error=%v", version, got, e)
		}
	}
	patch := func(body string) {
		t.Helper()
		o, e = policies.Patch(ctx, o.GetName(), types.MergePatchType, []byte(body), meta.PatchOptions{})
		if e != nil {
			t.Fatal(e)
		}
	}
	check(1, false)
	patch(`{"spec":{"suspended":true}}`)
	check(1, false)
	patch(`{"spec":{"suspended":false}}`)
	check(1, false)
	patch(`{"spec":{"retention":"1h"}}`)
	check(2, false)
	patch(`{"spec":{"retention":"2h"}}`)
	check(3, false)
	// Both edits happen before the next observation; even returning to identical
	// content cannot erase a missed Kubernetes spec generation.
	patch(`{"spec":{"retention":"1h"}}`)
	patch(`{"spec":{"retention":"2h"}}`)
	check(4, false)
	patch(`{"metadata":{"finalizers":["asservat.io/synthetic-source-test"]}}`)
	if e := policies.Delete(ctx, o.GetName(), meta.DeleteOptions{}); e != nil {
		t.Fatal(e)
	}
	check(4, true)
	patch(`{"metadata":{"finalizers":[]}}`)
	if _, e := reader.PolicySource(ctx); e == nil {
		t.Fatal("deleted source returned usable observation")
	}
	var replacement unstructured.Unstructured
	if e := json.Unmarshal(data, &replacement.Object); e != nil {
		t.Fatal(e)
	}
	if _, e := policies.Create(ctx, &replacement, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if e := observer.Reconcile(ctx); e == nil {
		t.Fatal("same-name replacement revived source")
	}
	t.Log("real Kubernetes policy source to SQL: read-only RBAC, pause/resume, intent edits, missed generations, UID tombstone and replacement rejection passed")
}
