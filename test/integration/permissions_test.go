package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	value "asservat.local/asservat/internal/domain/configuration"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func TestPermissionsWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_PERMISSION_FIXTURE")
	if path == "" {
		t.Skip("owned Kubernetes fixture required; run make permission-integration")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Config, Token string }
	if json.Unmarshal(b, &fixture) != nil {
		t.Fatal("invalid fixture")
	}
	admin, err := clientcmd.BuildConfigFromFlags("", fixture.Config)
	if err != nil {
		t.Fatal("fixture configuration")
	}
	admin.Timeout = 5 * time.Second
	core, err := kubernetes.NewForConfig(admin)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := dynamic.NewForConfig(admin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	control, err := core.CoreV1().Namespaces().Get(ctx, "asservat-system", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ns, err := core.CoreV1().Namespaces().Get(ctx, "payments", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cluster := "11111111-1111-4111-8111-111111111111"
	gr := schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "accessbindings"}
	bindings := writer.Resource(gr).Namespace(control.Name)
	sourceGR := schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "permissionsources"}
	for i := 0; i < 65; i++ {
		o := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": fmt.Sprintf("fixture-%03d", i), "namespace": control.Name}, "spec": map[string]any{"effect": "Allow", "subjects": []any{map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": "team-payments"}}, "roles": []any{"workload-maintainer"}, "scope": map[string]any{"clusterID": cluster, "namespaceRef": map[string]any{"name": ns.Name, "uid": string(ns.UID)}}, "reason": "synthetic binding"}}}
		if _, err := bindings.Create(ctx, o, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	source := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "PermissionSource", "metadata": map[string]any{"name": "fixture", "namespace": control.Name}, "spec": map[string]any{"enabled": true, "clusterID": cluster, "type": "namespaceMetadata", "namespaceSelector": map[string]any{"matchLabels": map[string]any{"example.invalid/managed": "true"}}, "excludedNamespaces": []any{"kube-system"}, "role": "evidence-owner", "maxDecisionAgeSeconds": int64(30), "maxNamespaces": int64(100), "protection": map[string]any{"mode": "administratorManaged", "reviewRef": "synthetic-unqualified"}, "metadataMapping": map[string]any{"field": "annotation", "key": "example.invalid/owner", "mode": "valueMap", "issuer": "https://id.example.invalid", "values": map[string]any{"payments": []any{"team-payments", "team-operations"}}}}}}
	if _, err := writer.Resource(sourceGR).Namespace(control.Name).Create(ctx, source, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Fresh config, not a copy of admin with lingering client cert/auth plugins.
	readerConfig := &rest.Config{Host: admin.Host, BearerToken: fixture.Token, TLSClientConfig: rest.TLSClientConfig{CAData: admin.CAData, CAFile: admin.CAFile, ServerName: admin.ServerName}}
	reader, err := kube.NewPermissionClient(readerConfig, cluster, value.NamespaceRef{Name: control.Name, UID: string(control.UID)}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := dynamic.NewForConfig(readerConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("paginated observation and multiple owner proposal", func(t *testing.T) {
		s, err := reader.PermissionSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Bindings) != 65 || len(s.Sources) != 1 || !s.SourcesComplete {
			t.Fatal("real paginated snapshot incomplete")
		}
		n, err := reader.NamespaceMetadata(ctx, value.NamespaceQuery{Namespace: value.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, LabelKeys: []string{"example.invalid/managed"}, AnnotationKeys: []string{"example.invalid/owner"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(n.Annotations) != 1 || n.Annotations["unrelated"] != "" {
			t.Fatal("unselected namespace data escaped")
		}
		p := value.ProposeNamespace(s.Sources[0], n, value.Target{ClusterID: cluster, Namespace: n.Namespace}, time.Now())
		if len(p.Candidates) != 2 || p.Reason != "RequiresProtectionQualification" {
			t.Fatal("synthetic review incorrectly conferred authority")
		}
	})
	t.Run("reader cannot write or read other scopes", func(t *testing.T) {
		if _, err := restricted.Resource(sourceGR).Namespace(control.Name).Create(ctx, source, meta.CreateOptions{}); !apierrors.IsForbidden(err) {
			t.Fatal("read role wrote source")
		}
		if _, err := restricted.Resource(gr).Namespace("other").List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(err) {
			t.Fatal("read role listed other scope")
		}
		for _, resource := range []string{"secrets", "pods"} {
			if _, err := restricted.Resource(schema.GroupVersionResource{Version: "v1", Resource: resource}).Namespace("payments").List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(err) {
				t.Fatal("reader saw workload data")
			}
		}
		_, err := reader.NamespaceMetadata(ctx, value.NamespaceQuery{Namespace: value.NamespaceRef{Name: "other", UID: "untrusted"}})
		if !errors.Is(err, value.ErrDenied) {
			t.Fatal("read role saw other namespace")
		}
	})
	t.Run("dry run conflict and malformed deny", func(t *testing.T) {
		o, err := bindings.Get(ctx, "fixture-000", meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		original := o.DeepCopy()
		_ = unstructured.SetNestedField(o.Object, "changed reason", "spec", "reason")
		if _, err := bindings.Update(ctx, o, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); err != nil {
			t.Fatal(err)
		}
		current, err := bindings.Get(ctx, o.GetName(), meta.GetOptions{})
		if err != nil || current.GetResourceVersion() != original.GetResourceVersion() {
			t.Fatal("dry run persisted")
		}
		if _, err := bindings.Update(ctx, o, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := bindings.Update(ctx, original, meta.UpdateOptions{}); !apierrors.IsConflict(err) {
			t.Fatal("stale replacement succeeded")
		}
		current, err = bindings.Get(ctx, o.GetName(), meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_ = unstructured.SetNestedField(current.Object, "Deny", "spec", "effect")
		_ = unstructured.SetNestedField(current.Object, true, "spec", "unknownAuthority")
		if _, err := bindings.Update(ctx, current, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if s, err := reader.PermissionSnapshot(ctx); err == nil || len(s.Bindings) != 0 {
			t.Fatal("malformed deny silently omitted")
		}
		current, err = bindings.Get(ctx, o.GetName(), meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		unstructured.RemoveNestedField(current.Object, "spec", "unknownAuthority")
		if _, err := bindings.Update(ctx, current, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		s, err := reader.PermissionSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if s.Bindings[0].Effect != "Deny" || s.Bindings[0].Resource.Generation < 2 {
			t.Fatal("current deny revision lost")
		}
	})
	t.Run("watch retains rapid ownership transitions", func(t *testing.T) {
		snapshot, err := reader.PermissionSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		stream, err := reader.WatchBindings(ctx, snapshot.BindingResourceVersion)
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		object, err := bindings.Get(ctx, "fixture-003", meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for _, team := range []string{"team-transient", "team-payments"} {
			subjects := []any{map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": team}}
			if err = unstructured.SetNestedSlice(object.Object, subjects, "spec", "subjects"); err != nil {
				t.Fatal(err)
			}
			object, err = bindings.Update(ctx, object, meta.UpdateOptions{})
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, team := range []string{"team-transient", "team-payments"} {
			for attempts := 0; ; attempts++ {
				if attempts >= 8 {
					t.Fatal("expected binding transition missing")
				}
				event, err := stream.Next(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if event.Type == "BOOKMARK" {
					continue
				}
				if event.Type != "MODIFIED" || event.Binding == nil || event.Binding.Resource.UID != string(object.GetUID()) || event.Binding.Subjects[0].ID != team {
					t.Fatalf("rapid transition lost: %+v", event)
				}
				break
			}
		}
	})

	t.Run("binding recreation and namespace UID pin", func(t *testing.T) {
		old, err := bindings.Get(ctx, "fixture-001", meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		uid, rv := old.GetUID(), old.GetResourceVersion()
		if err := bindings.Delete(ctx, old.GetName(), meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid, ResourceVersion: &rv}}); err != nil {
			t.Fatal(err)
		}
		replacement := old.DeepCopy()
		replacement.SetUID("")
		replacement.SetResourceVersion("")
		replacement.SetCreationTimestamp(meta.Time{})
		replacement.SetGeneration(0)
		replacement.SetManagedFields(nil)
		created, err := bindings.Create(ctx, replacement, meta.CreateOptions{})
		if err != nil || created.GetUID() == uid {
			t.Fatal("binding incarnation did not change")
		}
		if err := bindings.Delete(ctx, old.GetName(), meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid}}); !apierrors.IsConflict(err) {
			t.Fatal("old UID deleted replacement")
		}
		s, err := reader.PermissionSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, b := range s.Bindings {
			if b.Resource.Name == old.GetName() {
				found = b.Resource.UID == string(created.GetUID())
			}
		}
		if !found {
			t.Fatal("new binding incarnation not observed")
		}
		if _, err := reader.NamespaceMetadata(ctx, value.NamespaceQuery{Namespace: value.NamespaceRef{Name: ns.Name, UID: "replaced"}}); !errors.Is(err, value.ErrChanged) {
			t.Fatal("namespace UID mismatch accepted")
		}
	})
	encoded, _ := json.Marshal(readerConfig.TLSClientConfig.Insecure)
	if strings.TrimSpace(string(encoded)) != "false" {
		t.Fatal("fixture did not verify TLS")
	}
}
