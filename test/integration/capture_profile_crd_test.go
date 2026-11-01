package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	compiler "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type podTargetProfiles struct{ targets *kube.PodTargets }

func (r podTargetProfiles) ReadCaptureProfiles(ctx context.Context, q targets.ProfileCatalogRequest) (targets.ProfileCatalogAnswer, error) {
	return r.targets.ReadCaptureProfiles(ctx, q)
}
func (r podTargetProfiles) ListCaptureProfiles(ctx context.Context, q targets.ProfileListRequest) (targets.ProfileCatalogAnswer, error) {
	return r.targets.ListCaptureProfiles(ctx, q)
}

// REQ-CPR-001 against the chart's CaptureProfile CRD on a real API server:
// a published definition is immutable while availability may change, the
// object name is <name>.<version>, organization and namespace catalogs stay
// confined to their namespaces, and the compiler decodes what the product
// reader returns.
func TestCaptureProfilesWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_PERMISSION_FIXTURE")
	if path == "" {
		t.Skip("run make permission-integration")
	}
	var f struct{ Config string }
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	c, err := clientcmd.BuildConfigFromFlags("", f.Config)
	if err != nil {
		t.Fatal(err)
	}
	c.Timeout = 5 * time.Second
	api, err := kubernetes.NewForConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := dynamic.NewForConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	namespace := func(name string) value.NamespaceRef {
		ns, err := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = api.CoreV1().Namespaces().Delete(context.Background(), name, meta.DeleteOptions{}) })
		return value.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}
	}
	hub, team, other := namespace("profiles-hub"), namespace("profiles-team"), namespace("profiles-other")
	builtin, err := os.ReadFile("../../internal/application/planning/profiles/network-connections-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Definition map[string]any }
	if err = json.Unmarshal(builtin, &doc); err != nil {
		t.Fatal(err)
	}
	gr := schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "captureprofiles"}
	publish := func(ns, object, name, version string, enabled bool) (*unstructured.Unstructured, error) {
		return objects.Resource(gr).Namespace(ns).Create(ctx, &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "CaptureProfile",
			"metadata": map[string]any{"name": object},
			"spec":     map[string]any{"name": name, "version": version, "definition": doc.Definition, "availability": map[string]any{"enabled": enabled, "deprecated": false}}}}, meta.CreateOptions{})
	}
	org, err := publish(hub.Name, "team-network.v3", "team-network", "v3", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publish(team.Name, "local-network.v1", "local-network", "v1", true); err != nil {
		t.Fatal(err)
	}
	// Same name in an unrelated namespace: never visible to the team target.
	if _, err = publish(other.Name, "other-network.v1", "other-network", "v1", true); err != nil {
		t.Fatal(err)
	}
	if _, err = publish(team.Name, "network-connections.v2", "team-network", "v2", true); err == nil {
		t.Fatal("an object name other than <name>.<version> was admitted")
	}
	changed := org.DeepCopy()
	_ = unstructured.SetNestedField(changed.Object, "Changed", "spec", "definition", "displayName")
	if _, err = objects.Resource(gr).Namespace(hub.Name).Update(ctx, changed, meta.UpdateOptions{}); err == nil {
		t.Fatal("a published definition was mutated")
	}
	disabled := org.DeepCopy()
	_ = unstructured.SetNestedField(disabled.Object, false, "spec", "availability", "enabled")
	if _, err = objects.Resource(gr).Namespace(hub.Name).Update(ctx, disabled, meta.UpdateOptions{}); err != nil {
		t.Fatal("availability change refused:", err)
	}

	cluster := "00000000-0000-4000-8000-0000000000c1"
	client, err := kube.NewPermissionClient(c, cluster, hub, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	regional, err := kube.NewPodTargets(client)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := kube.NewCaptureProfileCatalog(client, hub, podTargetProfiles{regional})
	if err != nil {
		t.Fatal(err)
	}
	target := targets.PodResolution{Request: targets.Request{ClusterID: cluster, Namespace: team}}
	orgRef := planning.ProfileRef{Catalog: "organization", Name: "team-network", Version: "v3"}
	localRef := planning.ProfileRef{Catalog: "namespace", Name: "local-network", Version: "v1"}
	foreignRef := planning.ProfileRef{Catalog: "namespace", Name: "other-network", Version: "v1"}
	read, err := catalog.ReadCatalogProfiles(ctx, target, []planning.ProfileRef{orgRef, localRef, foreignRef})
	if err != nil || len(read) != 2 || read[0].Ref != orgRef || read[0].SourceUID != string(org.GetUID()) || read[0].Enabled || read[1].Ref != localRef || read[1].SourceNamespaceUID != team.UID {
		t.Fatalf("read = %+v, %v", read, err)
	}
	listed, err := catalog.ListCatalogProfiles(ctx, target, "")
	if err != nil {
		t.Fatal(err)
	}
	described := compiler.DescribeProfiles("", listed)
	if len(described) != 4 || described[2].Ref != orgRef || described[2].Available || described[3].Ref != localRef || !described[3].Available {
		t.Fatalf("listed = %+v", described)
	}
	if digest, ok := compiler.BuiltinProfileDigest("network-connections"); !ok || described[2].Digest == digest {
		t.Fatal("a renamed organization definition kept the builtin identity")
	}
	target.Request.Namespace.UID = other.UID
	if _, err = catalog.ListCatalogProfiles(ctx, target, "namespace"); err == nil {
		t.Fatal("a replaced namespace was listed")
	}
}
