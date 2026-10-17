package integration

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// This starts the actual compiled role with kubelet-owned token projections.
// The fixture provisions synthetic provider credentials and initial recovery
// acceptance separately; neither is a production installation qualification.
func startNativeHubWorker(t *testing.T, ctx context.Context, api kubernetes.Interface, kc *rest.Config, c contracts.HubWorkerDeployment, image, dir, administrator string) chan error {
	t.Helper()
	ns := c.Namespace.Name
	p := kube.HubWorkerWorkloadPlan{Namespace: ns, Name: "worker", ServiceAccount: "worker", Configuration: "worker-inputs", Credentials: "worker-providers", Image: image, FleetSource: c.FleetSource.Name, OwnerSource: c.OwnerSource.Name, FleetGuard: c.FleetGuard.Name, OwnerGuard: c.OwnerGuard.Name, LeaderLease: c.LeaderLease.Name}
	w, err := kube.BuildHubWorkerWorkload(p)
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := api.AppsV1().Deployments(ns).Create(ctx, w.Deployment, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan := cfg.OwnerWorkloadAdministration{Name: ns + "-namespace", Deployment: deployment.Name, DeploymentUID: string(deployment.UID), ControlNamespace: cfg.NamespaceRef{Name: ns, UID: c.Namespace.UID}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: administrator}}, ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: c.FleetSource.Name, ServiceAccount: p.ServiceAccount}, {ConfigMap: c.OwnerSource.Name, ServiceAccount: p.ServiceAccount}}, SchedulingLeases: []cfg.OwnerSchedulingLease{{Lease: c.LeaderLease.Name, ServiceAccount: p.ServiceAccount}}}
	policy, binding, err := kube.OwnerWorkloadAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.CoreV1().ServiceAccounts(ns).Create(ctx, w.Account, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.RbacV1().Roles(ns).Create(ctx, w.Role, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.RbacV1().RoleBindings(ns).Create(ctx, w.Binding, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.RbacV1().ClusterRoles().Create(ctx, w.ClusterRole, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.RbacV1().ClusterRoleBindings().Create(ctx, w.ClusterBinding, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	inputs, err := os.ReadFile(filepath.Join(dir, "deployment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = api.CoreV1().ConfigMaps(ns).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: p.Configuration}, Immutable: ptr.To(true), Data: map[string]string{"deployment.json": string(inputs)}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	secret := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: p.Credentials}, Immutable: ptr.To(true), Data: map[string][]byte{}}
	for _, file := range w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources[1].Secret.Items {
		data, e := os.ReadFile(filepath.Join(dir, file.Key))
		if e != nil {
			t.Fatal(e)
		}
		secret.Data[file.Key] = data
	}
	if _, err = api.CoreV1().Secrets(ns).Create(ctx, secret, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, v := range secret.Data {
		clear(v)
	}
	// Deployment-controller status/annotation updates can race installation.
	// Retry only the same stored UID and unchanged protected specification.
	original := deployment.DeepCopy()
	for attempt := 0; attempt < 5; attempt++ {
		deployment, err = api.AppsV1().Deployments(ns).Get(ctx, p.Name, meta.GetOptions{})
		if err != nil || deployment.UID != original.UID || !reflect.DeepEqual(deployment.Spec, original.Spec) {
			t.Fatal("deployment changed before launch", err)
		}
		deployment.Spec.Replicas = ptr.To(int32(1))
		deployment, err = api.AppsV1().Deployments(ns).Update(ctx, deployment, meta.UpdateOptions{})
		if !apierrors.IsConflict(err) {
			break
		}
	}
	if err != nil {
		t.Fatal("native worker launch", err)
	}
	watchCtx, cancel := context.WithCancel(ctx)
	done, joined := make(chan error, 1), make(chan struct{})
	selector := "asservat.io/workload=" + p.Name
	t.Cleanup(func() {
		cancel()
		<-joined
		cleanup, end := context.WithTimeout(context.Background(), 60*time.Second)
		defer end()
		if t.Failed() {
			pods, e := api.CoreV1().Pods(ns).List(cleanup, meta.ListOptions{LabelSelector: selector})
			if e == nil {
				for _, pod := range pods.Items {
					t.Log("native worker status", pod.UID, pod.Status.Phase)
					for _, v := range pod.Status.ContainerStatuses {
						t.Log("process", v.Name, "image", v.ImageID, "restarts", v.RestartCount, "last", v.LastTerminationState.Terminated)
					}
					r, e := api.CoreV1().Pods(ns).GetLogs(pod.Name, &core.PodLogOptions{LimitBytes: ptr.To(int64(4096))}).Stream(cleanup)
					if e == nil {
						v, _ := io.ReadAll(io.LimitReader(r, 4096))
						r.Close()
						t.Log(string(v))
					}
				}
			}
		}
		verifyHubGarbageCollector(t, cleanup, api, kc, ns, deployment.Name, selector, p.Credentials, p.Configuration)
		if e := api.AppsV1().Deployments(ns).Delete(cleanup, deployment.Name, meta.DeleteOptions{PropagationPolicy: ptr.To(meta.DeletePropagationForeground)}); e != nil {
			t.Error("worker cleanup", e)
		}
		noted := false
		started := time.Now()
		for cleanup.Err() == nil {
			pods, e := api.CoreV1().Pods(ns).List(cleanup, meta.ListOptions{LabelSelector: selector})
			dep, depErr := api.AppsV1().Deployments(ns).Get(cleanup, deployment.Name, meta.GetOptions{})
			if e == nil && len(pods.Items) == 0 && apierrors.IsNotFound(depErr) {
				return
			}
			if !noted && time.Since(started) > 5*time.Second {
				noted = true
				if depErr == nil {
					t.Log("deleting Deployment", dep.DeletionTimestamp, dep.Finalizers)
				}
				if e == nil {
					for _, pod := range pods.Items {
						t.Log("remaining Pod", pod.Name, "deleting", pod.DeletionTimestamp, "finalizers", pod.Finalizers)
					}
				}
				replicas, e := api.AppsV1().ReplicaSets(ns).List(cleanup, meta.ListOptions{LabelSelector: selector})
				if e == nil {
					for _, r := range replicas.Items {
						t.Log("remaining ReplicaSet", r.Name, "deleting", r.DeletionTimestamp, "finalizers", r.Finalizers)
					}
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		diagnostic, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		controllers, e := api.CoreV1().Pods("kube-system").List(diagnostic, meta.ListOptions{LabelSelector: "component=kube-controller-manager"})
		if e == nil {
			for _, pod := range controllers.Items {
				r, e := api.CoreV1().Pods("kube-system").GetLogs(pod.Name, &core.PodLogOptions{TailLines: ptr.To(int64(100)), LimitBytes: ptr.To(int64(32768))}).Stream(diagnostic)
				if e == nil {
					v, _ := io.ReadAll(io.LimitReader(r, 32768))
					r.Close()
					for _, line := range strings.Split(string(v), "\n") {
						if strings.Contains(line, ns) {
							t.Log("controller teardown", line)
						}
					}
				}
			}
		}
		t.Error("native worker Pods did not terminate")
	})
	go func() {
		defer close(joined)
		reported := false
		for {
			pods, e := api.CoreV1().Pods(ns).List(watchCtx, meta.ListOptions{LabelSelector: selector})
			if e == nil {
				for _, pod := range pods.Items {
					for _, status := range pod.Status.ContainerStatuses {
						if status.ImageID != "" && !strings.HasSuffix(status.ImageID, strings.Split(image, "@")[1]) {
							done <- errors.New("native worker image identity mismatch")
							return
						}
						if status.ImageID != "" && !reported {
							reported = true
							t.Log("observed native Pod", pod.UID, "image", status.ImageID)
						}
						if status.RestartCount > 0 || status.State.Terminated != nil {
							done <- errors.New("native worker process stopped")
							return
						}
					}
				}
			}
			select {
			case <-watchCtx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	t.Log("native worker image", image, "Deployment", deployment.UID, "Restricted Pod with projected API tokens; native timed token renewal not measured")
	return done
}

// Impersonation is a fixture administrator operation. No production role can
// impersonate this account, and no extra rights are bound to the hub worker.
func verifyHubGarbageCollector(t *testing.T, ctx context.Context, admin kubernetes.Interface, kc *rest.Config, ns, name, selector, secret, config string) {
	t.Helper()
	gcConfig := rest.CopyConfig(kc)
	gcConfig.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:kube-system:generic-garbage-collector", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"}}
	gc, err := kubernetes.NewForConfig(gcConfig)
	if err != nil {
		t.Error(err)
		return
	}
	patch := meta.PatchOptions{DryRun: []string{meta.DryRunAll}, FieldValidation: "Strict"}
	clean := []byte(`{"metadata":{"finalizers":[]}}`)
	allowed := func(label string, e error) {
		t.Helper()
		if e != nil {
			t.Error("garbage collector metadata update denied", label, e)
		}
	}
	denied := func(label string, e error) {
		t.Helper()
		var status apierrors.APIStatus
		expected := "ValidatingAdmissionPolicy '" + ns + "-namespace' with binding '" + ns + "-namespace' denied request: Asservat private hub namespace requires an installation administrator or a qualified Kubernetes controller operation."
		if errors.As(e, &status) && status.Status().Details != nil {
			for _, cause := range status.Status().Details.Causes {
				if cause.Message == expected {
					return
				}
			}
		}
		t.Error("expected exact namespace denial", label, e)
	}
	_, err = gc.AppsV1().Deployments(ns).Patch(ctx, name, types.MergePatchType, clean, patch)
	allowed("Deployment", err)
	_, err = gc.AppsV1().Deployments(ns).Patch(ctx, name, types.MergePatchType, []byte(`{"spec":{"replicas":3}}`), patch)
	denied("Deployment spec", err)
	for _, body := range []string{`{"metadata":{"labels":{"gc-forged":"true"}}}`, `{"metadata":{"annotations":{"gc-forged":"true"}}}`} {
		_, err = gc.AppsV1().Deployments(ns).Patch(ctx, name, types.MergePatchType, []byte(body), patch)
		denied("Deployment metadata authority", err)
	}
	rs, err := admin.AppsV1().ReplicaSets(ns).List(ctx, meta.ListOptions{LabelSelector: selector})
	if err != nil || len(rs.Items) != 1 {
		t.Error("GC ReplicaSet fixture", err)
		return
	}
	_, err = gc.AppsV1().ReplicaSets(ns).Patch(ctx, rs.Items[0].Name, types.MergePatchType, clean, patch)
	allowed("ReplicaSet", err)
	_, err = gc.AppsV1().ReplicaSets(ns).Patch(ctx, rs.Items[0].Name, types.MergePatchType, []byte(`{"spec":{"replicas":3}}`), patch)
	denied("ReplicaSet spec", err)
	pods, err := admin.CoreV1().Pods(ns).List(ctx, meta.ListOptions{LabelSelector: selector})
	if err != nil || len(pods.Items) != 1 {
		t.Error("GC Pod fixture", err)
		return
	}
	nodeConfig := rest.CopyConfig(kc)
	nodeConfig.Impersonate = rest.ImpersonationConfig{UserName: "system:node:" + pods.Items[0].Spec.NodeName, Groups: []string{"system:nodes", "system:authenticated"}}
	node, e := kubernetes.NewForConfig(nodeConfig)
	if e != nil {
		t.Error(e)
	} else {
		e = node.CoreV1().Pods(ns).Delete(ctx, pods.Items[0].Name, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}, Preconditions: &meta.Preconditions{UID: &pods.Items[0].UID}})
		denied("kubelet cannot initiate deletion of a running Pod", e)
	}
	_, err = gc.CoreV1().Pods(ns).Patch(ctx, pods.Items[0].Name, types.MergePatchType, clean, patch)
	allowed("Pod", err)
	_, err = gc.CoreV1().Pods(ns).Patch(ctx, pods.Items[0].Name, types.StrategicMergePatchType, []byte(`{"spec":{"containers":[{"name":"worker","image":"synthetic.invalid/foreign:changed"}]}}`), patch)
	denied("Pod image", err)
	_, err = gc.CoreV1().Secrets(ns).Patch(ctx, secret, types.MergePatchType, clean, patch)
	denied("Secret", err)
	_, err = gc.CoreV1().ConfigMaps(ns).Patch(ctx, config, types.MergePatchType, clean, patch)
	denied("configuration", err)
	t.Log("GC dry-run checks: metadata maintenance allowed for Deployment/ReplicaSet/Pod; spec, labels, annotations, Secret and configuration changes denied")
}
