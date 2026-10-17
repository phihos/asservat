package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/targets"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// The fixture grants read-only candidate listing separately from existing
// target GET rights. Actual controllers, labels, owner references, node UIDs
// and boot IDs are observed; no fixture observation grants product authority.
func TestWorkloadTargetsWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run make context-integration for owned real Kubernetes fixtures")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	var f fixture
	if json.Unmarshal(data, &f) != nil || len(f.Clusters) != 2 {
		t.Fatal("invalid owned fixture")
	}
	clear(data)
	for index, cluster := range f.Clusters {
		t.Run([]string{"cluster-a", "cluster-b"}[index], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			config, err := clientcmd.BuildConfigFromFlags("", cluster.Config)
			if err != nil {
				t.Fatal(err)
			}
			admin, err := kubernetes.NewForConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			ns := cluster.Pod.Namespace
			clusterID := []string{"00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000005"}[index]
			reader := rest.CopyConfig(config)
			reader.BearerToken, reader.BearerTokenFile = cluster.TargetToken, ""
			reader.CertData, reader.KeyData, reader.CertFile, reader.KeyFile = nil, nil, "", ""
			observations, err := kube.NewPermissionClient(reader, clusterID, cfg.NamespaceRef{Name: ns, UID: cluster.Pod.NamespaceUID}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			resolver, err := kube.NewPodTargets(observations)
			if err != nil {
				t.Fatal(err)
			}
			named := targets.WorkloadRequest{ClusterID: clusterID, Namespace: ns, Kind: "Deployment", Name: "fixture"}
			if _, err := resolver.ResolveWorkload(ctx, named); !errors.Is(err, targets.ErrDenied) {
				t.Fatalf("GET-only reader gained candidate listing: %v", err)
			}
			// An explicit Pod avoids LIST but retains the actual workload budget.
			direct, err := resolver.ResolveWorkload(ctx, targets.WorkloadRequest{ClusterID: clusterID, Namespace: ns, Kind: "Pod", Name: cluster.Pod.Name})
			if err != nil || direct.Pin != cluster.Pod || direct.Request.Workload.Kind != "Deployment" || direct.Request.Workload.UID != cluster.WorkloadUID || direct.NodeUID != cluster.NodeUID || direct.NodeBootID != cluster.NodeBootID {
				t.Fatalf("direct Pod did not retain independently observed workload/node identity: %v", err)
			}
			role, err := admin.RbacV1().Roles(ns).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "workload-target-list", Namespace: ns}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}}}}, meta.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
				defer done()
				if err := admin.RbacV1().Roles(ns).Delete(cleanup, role.Name, exactTargetDelete(role.UID)); err != nil && !apierrors.IsNotFound(err) {
					t.Error(err)
				}
			})
			binding, err := admin.RbacV1().RoleBindings(ns).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: role.Name, Namespace: ns}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "target-reader", Namespace: ns}}, RoleRef: rbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: role.Name}}, meta.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
				defer done()
				if err := admin.RbacV1().RoleBindings(ns).Delete(cleanup, binding.Name, exactTargetDelete(binding.UID)); err != nil && !apierrors.IsNotFound(err) {
					t.Error(err)
				}
			})
			original, err := admin.AppsV1().Deployments(ns).Get(ctx, "fixture", meta.GetOptions{})
			if err != nil || string(original.UID) != cluster.WorkloadUID {
				t.Fatal("original fixture workload changed")
			}
			foreignSpec := original.Spec.DeepCopy()
			foreignSpec.Replicas = ptr.To(int32(1))
			foreign, err := admin.AppsV1().Deployments(ns).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "aaa-workload-foreign", Namespace: ns}, Spec: *foreignSpec}, meta.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
				defer done()
				if err := admin.AppsV1().Deployments(ns).Delete(cleanup, foreign.Name, exactTargetDelete(foreign.UID)); err != nil && !apierrors.IsNotFound(err) {
					t.Error(err)
					return
				}
				if err := wait.PollUntilContextCancel(cleanup, 100*time.Millisecond, true, func(ctx context.Context) (bool, error) {
					_, err := admin.AppsV1().Deployments(ns).Get(ctx, foreign.Name, meta.GetOptions{})
					return apierrors.IsNotFound(err), nonNotFound(err)
				}); err != nil {
					t.Error("foreign Deployment normal cleanup:", err)
				}
			})
			var foreignPod core.Pod
			if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 20*time.Second, true, func(ctx context.Context) (bool, error) {
				pods, err := admin.CoreV1().Pods(ns).List(ctx, meta.ListOptions{LabelSelector: "app=fixture"})
				if err != nil {
					return false, err
				}
				for _, pod := range pods.Items {
					if strings.HasPrefix(pod.Name, foreign.Name+"-") && pod.Spec.NodeName != "" && pod.DeletionTimestamp == nil {
						foreignPod = pod
						return true, nil
					}
				}
				return false, nil
			}); err != nil {
				t.Fatal("foreign scheduled fixture pod:", err)
			}
			if foreignPod.Name >= cluster.Pod.Name {
				t.Fatal("fixture must put the matching-label foreign pod before the real target")
			}
			var selected targets.PodResolution
			if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
				out, err := resolver.ResolveWorkload(ctx, named)
				if errors.Is(err, targets.ErrDenied) {
					return false, nil // Wait only for the newly created fixture RBAC.
				}
				selected = out
				return err == nil, err
			}); err != nil || selected.Pin != cluster.Pod || selected.Request.Workload.UID != cluster.WorkloadUID || !selected.Valid(time.Now()) {
				t.Fatalf("foreign matching-label workload influenced selection: %v", err)
			}
			foreignSelected, err := resolver.ResolveWorkload(ctx, targets.WorkloadRequest{ClusterID: clusterID, Namespace: ns, Kind: "Pod", Name: foreignPod.Name})
			if err != nil || foreignSelected.Request.Workload.UID != string(foreign.UID) || foreignSelected.Request.Workload.UID == selected.Request.Workload.UID {
				t.Fatalf("foreign direct Pod lost its actual workload identity: %v", err)
			}
			if err := admin.CoreV1().Pods(ns).Delete(ctx, foreignPod.Name, exactTargetDelete(foreignPod.UID)); err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ResolvePod(ctx, foreignSelected.Request); !errors.Is(err, targets.ErrChanged) {
				t.Fatalf("deleted frozen pod was replaced by a sibling: %v", err)
			}
			qualifyStatefulTarget(t, ctx, admin, resolver, original, clusterID)
			if err := admin.RbacV1().RoleBindings(ns).Delete(ctx, binding.Name, exactTargetDelete(binding.UID)); err != nil {
				t.Fatal(err)
			}
			if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
				_, err := resolver.ResolveWorkload(ctx, named)
				if err == nil {
					return false, nil
				}
				if errors.Is(err, targets.ErrDenied) {
					return true, nil
				}
				return false, err
			}); err != nil {
				t.Fatal("list revocation did not take effect:", err)
			}
		})
	}
}

func exactTargetDelete(uid types.UID) meta.DeleteOptions {
	return meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid}, PropagationPolicy: ptr.To(meta.DeletePropagationForeground)}
}

func nonNotFound(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func qualifyStatefulTarget(t *testing.T, ctx context.Context, admin *kubernetes.Clientset, resolver *kube.PodTargets, original *apps.Deployment, clusterID string) {
	t.Helper()
	ns, name := original.Namespace, "workload-target-stateful"
	labels := map[string]string{"app": name}
	service, err := admin.CoreV1().Services(ns).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns}, Spec: core.ServiceSpec{ClusterIP: core.ClusterIPNone, Selector: labels, Ports: []core.ServicePort{{Name: "synthetic", Port: 80}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if err := admin.CoreV1().Services(ns).Delete(cleanup, service.Name, exactTargetDelete(service.UID)); err != nil && !apierrors.IsNotFound(err) {
			t.Error(err)
		}
	})
	template := original.Spec.Template.DeepCopy()
	template.Labels = labels
	stateful, err := admin.AppsV1().StatefulSets(ns).Create(ctx, &apps.StatefulSet{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns}, Spec: apps.StatefulSetSpec{Replicas: ptr.To(int32(1)), ServiceName: name, Selector: &meta.LabelSelector{MatchLabels: labels}, Template: *template}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if err := admin.AppsV1().StatefulSets(ns).Delete(cleanup, stateful.Name, exactTargetDelete(stateful.UID)); err != nil && !apierrors.IsNotFound(err) {
			t.Error(err)
			return
		}
		if err := wait.PollUntilContextCancel(cleanup, 100*time.Millisecond, true, func(ctx context.Context) (bool, error) {
			_, err := admin.AppsV1().StatefulSets(ns).Get(ctx, stateful.Name, meta.GetOptions{})
			return apierrors.IsNotFound(err), nonNotFound(err)
		}); err != nil {
			t.Error("StatefulSet normal cleanup:", err)
		}
	})
	if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 20*time.Second, true, func(ctx context.Context) (bool, error) {
		pod, err := admin.CoreV1().Pods(ns).Get(ctx, name+"-0", meta.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return err == nil && pod.Spec.NodeName != "", err
	}); err != nil {
		t.Fatal("StatefulSet scheduled fixture pod:", err)
	}
	resolved, err := resolver.ResolveWorkload(ctx, targets.WorkloadRequest{ClusterID: clusterID, Namespace: ns, Kind: "StatefulSet", Name: name})
	if err != nil || resolved.Request.PodName != name+"-0" || resolved.Request.Workload.UID != string(stateful.UID) || resolved.Pin.ControllerUID != string(stateful.UID) || !resolved.Valid(time.Now()) {
		t.Fatalf("actual StatefulSet ownership resolution: %v", err)
	}
}
