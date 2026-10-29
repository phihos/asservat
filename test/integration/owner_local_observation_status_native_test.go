package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Real API objects/status patches and bound TokenReview; installer pins and the
// operation process binding are fixture inputs, not installed authority proof.
func TestOwnerLocalObservationCallerStatusWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("owned Kubernetes metadata fixture required")
	}
	raw, err := os.ReadFile(path)
	var f fixture
	if err != nil || json.Unmarshal(raw, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("owned fixture unavailable", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	x := newOwnerObservationNativeCostFixture(t, ctx, f)
	admin, err := kubernetes.NewForConfig(x.config)
	if err != nil {
		t.Fatal(err)
	}
	ns := x.pool.Namespace
	sa, err := admin.CoreV1().ServiceAccounts(ns).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "caller"}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	original, err := admin.AppsV1().Deployments(ns).Get(ctx, x.pool.Deployment, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	template := *original.Spec.Template.DeepCopy()
	template.Labels = map[string]string{"app": "caller"}
	template.Spec.ServiceAccountName, template.Spec.DeprecatedServiceAccount = "caller", "caller"
	d, err := admin.AppsV1().Deployments(ns).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "caller"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Selector: &meta.LabelSelector{MatchLabels: template.Labels}, Template: template}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var pod core.Pod
	err = wait.PollUntilContextCancel(ctx, 100*time.Millisecond, true, func(c context.Context) (bool, error) {
		list, e := admin.CoreV1().Pods(ns).List(c, meta.ListOptions{LabelSelector: "app=caller"})
		if e != nil {
			return false, e
		}
		if len(list.Items) == 1 && list.Items[0].Status.Phase == core.PodRunning && list.Items[0].DeletionTimestamp == nil {
			pod = list.Items[0]
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		t.Fatal("actual caller startup", err)
	}
	d, err = admin.AppsV1().Deployments(ns).Get(ctx, d.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kube.ConnectorAPITemplateDigest(d.Spec.Template)
	if err != nil {
		t.Fatal(err)
	}
	roleName := ns + "-caller"
	if _, err = admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: roleName}, Rules: []rbac.PolicyRule{{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, e := range []error{admin.RbacV1().ClusterRoleBindings().Delete(c, roleName, meta.DeleteOptions{}), admin.RbacV1().ClusterRoles().Delete(c, roleName, meta.DeleteOptions{})} {
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("caller scoped role cleanup", e)
			}
		}
	})
	subject := []rbac.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: "observer"}}
	if _, err = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: roleName}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: roleName}, Subjects: subject}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	rules := []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{"caller"}, Verbs: []string{"get"}}, {APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"caller"}, Verbs: []string{"get"}}}
	if _, err = admin.RbacV1().Roles(ns).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "caller"}, Rules: rules}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.RbacV1().RoleBindings(ns).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "caller"}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "caller"}, Subjects: subject}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	token, err := admin.CoreV1().ServiceAccounts(ns).CreateToken(ctx, "caller", &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: []string{value.ClusterObservationAudience(x.pool.InstallationID)}, ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("real Pod-bound caller token", err)
	}
	pin := value.ClusterObservationCallerPin{RootID: x.pin.RootID, InstallationID: x.pool.InstallationID, ClusterID: x.pool.ClusterID, Namespace: x.plan.ControlNamespace, Account: sa.Name, AccountUID: string(sa.UID), Deployment: d.Name, DeploymentUID: string(d.UID), TemplateDigest: digest, ImageDigest: x.pin.ImageDigest, ProtectionDigest: x.pin.ProtectionDigest}
	var reads, patches, confirmed int
	critical := false
	var firstRV string
	config := &rest.Config{Host: x.config.Host, BearerToken: x.observerToken, TLSClientConfig: rest.TLSClientConfig{CAData: x.config.CAData, CAFile: x.config.CAFile}, WrapTransport: func(next http.RoundTripper) http.RoundTripper {
		return ownerProbeRoundTripper(func(r *http.Request) (*http.Response, error) {
			target := r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+ns+"/pods/"+pod.Name
			if !target {
				return next.RoundTrip(r)
			}
			reads++
			message := fmt.Sprintf("caller-status-%d", reads)
			if reads%2 == 0 {
				body, _ := json.Marshal(map[string]any{"metadata": map[string]string{"uid": string(pod.UID)}, "status": map[string]string{"message": message}})
				sub := []string{"status"}
				if critical {
					body, _ = json.Marshal(map[string]any{"metadata": map[string]any{"uid": string(pod.UID), "annotations": map[string]string{"asservat.io/caller-mutation": "changed"}}})
					sub = nil
				}
				changed, e := admin.CoreV1().Pods(ns).Patch(r.Context(), pod.Name, types.MergePatchType, body, meta.PatchOptions{}, sub...)
				if e != nil {
					return nil, fmt.Errorf("actual caller PATCH: %w", e)
				}
				if changed.UID != pod.UID || changed.ResourceVersion == firstRV || (!critical && changed.Status.Message != message) || (critical && changed.Annotations["asservat.io/caller-mutation"] != "changed") {
					return nil, fmt.Errorf("actual PATCH did not establish mutation")
				}
				patches++
			}
			response, e := next.RoundTrip(r)
			if e != nil {
				return response, e
			}
			data, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
			_ = response.Body.Close()
			if e != nil || len(data) > 1<<20 {
				return nil, fmt.Errorf("bounded actual Pod response unavailable")
			}
			response.Body = io.NopCloser(bytes.NewReader(data)) // exact bytes; no response editing
			var actual core.Pod
			if json.Unmarshal(data, &actual) != nil || response.StatusCode != 200 {
				return nil, fmt.Errorf("actual Pod GET unavailable")
			}
			if reads%2 == 1 {
				firstRV = actual.ResourceVersion
			} else {
				if actual.UID != pod.UID || actual.ResourceVersion == firstRV || (!critical && actual.Status.Message != message) || (critical && actual.Annotations["asservat.io/caller-mutation"] != "changed") {
					return nil, fmt.Errorf("second actual GET did not reflect mutation")
				}
				confirmed++
			}
			return response, nil
		})
	}}
	observer, err := kube.NewPermissionClient(config, x.pool.ClusterID, x.plan.ControlNamespace, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	// The guard must share the observer instance, as the real constructor requires.
	probeConfig := rest.CopyConfig(config)
	probeConfig.BearerToken = x.probeToken
	probeConfig.WrapTransport = nil
	probe, err := kube.NewPermissionClient(probeConfig, x.pool.ClusterID, x.plan.ControlNamespace, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := kube.NewOwnerWorkloadProtection(observer, probe, x.plan, x.guardPin)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := kube.NewOwnerLocalObservationOperationReader(observer, guard, x.pin, pin)
	if err != nil {
		t.Fatal(err)
	}
	binding := value.OwnerBinding{InstallationID: x.pool.InstallationID, ClusterID: x.pool.ClusterID, IssuerEpoch: x.pool.IssuerEpoch, PodUID: string(x.pod.UID), ProcessEpoch: custodyID()}
	for _, mode := range []string{"informational-status", "critical-annotation"} {
		t.Run(mode, func(t *testing.T) {
			critical = mode == "critical-annotation"
			reads, patches, confirmed = 0, 0, 0
			started := time.Now().UTC()
			until := started.Add(5 * time.Second)
			call, stop := context.WithDeadline(ctx, until)
			defer stop()
			request := value.OwnerObservationRequest{RootID: x.pin.RootID, ID: custodyID(), Challenge: custodyID(), RequestedAt: started, NotAfter: until}
			op, e := reader.Begin(call, request, binding, []byte(token.Status.Token), string(pod.UID))
			if critical {
				if op != nil {
					op.Close()
				}
				var step interface{ FixedStep() string }
				if !errors.Is(e, cfg.ErrChanged) || call.Err() != nil || !errors.As(e, &step) || !strings.HasSuffix(step.FixedStep(), "caller-objects") || reads != 2 || patches != 1 || confirmed != 1 {
					t.Fatal("critical real mutation not consumer-refused", e, reads, patches, confirmed)
				}
				return
			}
			if e != nil {
				t.Fatal("real status-only caller rejected", e, reads, patches, confirmed)
			}
			defer op.Close()
			first, e := op.Original(call)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = op.Claim(call, []byte(token.Status.Token), string(pod.UID)); e != nil {
				t.Fatal(e)
			}
			final, e := op.Final(call)
			if e != nil || !final.Final || !final.ObservedAt.Equal(first.ObservedAt) || final.FreshUntil.After(first.FreshUntil) || reads != 6 || patches != 3 || confirmed != 3 || call.Err() != nil {
				t.Fatal("final native caller proof", e, reads, patches, confirmed)
			}
			t.Logf("actual caller status changes=%d reads=%d elapsed=%s original-budget-left=%s", confirmed, reads, time.Since(started), time.Until(final.FreshUntil))
		})
	}
}
