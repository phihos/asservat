package integration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	admission "k8s.io/api/admissionregistration/v1"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type ownerProbeRoundTripper func(*http.Request) (*http.Response, error)

func (f ownerProbeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// These are actual admission/RBAC/controller checks in the owned fixture. They
// do not claim historical installation integrity, process attestation or issuer
// activation. No observed application namespace is subjected to this policy.
func exerciseOwnerWorkloadProtection(t *testing.T, ctx context.Context, admin kubernetes.Interface, config *rest.Config, pool value.OwnerPool, podName string, protected func(*kube.OwnerWorkloadProtection, *kube.PermissionClient)) {
	t.Helper()
	who, err := admin.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan := cfg.OwnerWorkloadAdministration{ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: "owner-pool", ServiceAccount: "owner-config-probe"}}, Name: "asservat-owner-workload", Deployment: pool.Deployment, DeploymentUID: pool.DeploymentUID, ControlNamespace: cfg.NamespaceRef{Name: pool.Namespace, UID: pool.NamespaceUID}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}
	var advanceBeforeProbe atomic.Bool
	makeClient := func(name string) (*kube.PermissionClient, kubernetes.Interface) {
		t.Helper()
		if _, e := admin.CoreV1().ServiceAccounts(pool.Namespace).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		token, e := admin.CoreV1().ServiceAccounts(pool.Namespace).CreateToken(ctx, name, &auth.TokenRequest{}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		limited := &rest.Config{Host: config.Host, BearerToken: token.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: config.CAData, CAFile: config.CAFile}}
		if name == "owner-workload-probe" {
			limited.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
				return ownerProbeRoundTripper(func(r *http.Request) (*http.Response, error) {
					isProbe := r.Method == http.MethodPut && r.URL.Path == "/apis/apps/v1/namespaces/"+pool.Namespace+"/deployments/"+pool.Deployment && r.URL.Query().Get("dryRun") == "All"
					if isProbe && advanceBeforeProbe.CompareAndSwap(true, false) {
						// A synthetic installer write deterministically advances the
						// resourceVersion after the observer GET, like a controller
						// status update during rollout. Product permissions are unchanged.
						_, e := admin.AppsV1().Deployments(pool.Namespace).Patch(r.Context(), pool.Deployment, types.MergePatchType, []byte(`{"metadata":{"annotations":{"asservat-test/probe-race":"advanced"}}}`), meta.PatchOptions{})
						if e != nil {
							return nil, e
						}
					}
					response, e := next.RoundTrip(r)
					if isProbe && e == nil && response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusUnprocessableEntity {
						body, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
						_ = response.Body.Close()
						response.Body = io.NopCloser(bytes.NewReader(body))
						t.Logf("synthetic owner probe response: HTTP %d, content-type=%q, body=%q, read=%v", response.StatusCode, response.Header.Get("Content-Type"), body, readErr)
					}
					return response, e
				})
			}
		}
		reader, e := kube.NewPermissionClient(limited, pool.ClusterID, plan.ControlNamespace, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		api, e := kubernetes.NewForConfig(limited)
		if e != nil {
			t.Fatal(e)
		}
		return reader, api
	}
	reader, readonly := makeClient("owner-workload-reader")
	probe, attacker := makeClient("owner-workload-probe")
	_, err = admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: plan.Name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{pool.Namespace}, Verbs: []string{"get"}}, {APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{plan.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: plan.Name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "owner-workload-reader", Namespace: pool.Namespace}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: plan.Name}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"owner-workload-reader", "owner-workload-probe"} {
		rules := []rbac.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{pool.Deployment}, Verbs: []string{"get"}}}
		if name == "owner-workload-probe" {
			rules = append(rules, rbac.PolicyRule{APIGroups: []string{"", "apps", "batch", "rbac.authorization.k8s.io"}, Resources: []string{"*"}, Verbs: []string{"create", "update", "delete"}})
		}
		_, err = admin.RbacV1().Roles(pool.Namespace).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: rules}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = admin.RbacV1().RoleBindings(pool.Namespace).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: name, Namespace: pool.Namespace}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: name}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	policy, binding, err := kube.OwnerWorkloadAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	binding, err = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pin := kube.GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion}
	guard, err := kube.NewOwnerWorkloadProtection(reader, probe, plan, pin)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(15 * time.Second)
	for time.Now().Before(until) {
		_, _, err = guard.Current(ctx)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		current, _ := admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, plan.Name, meta.GetOptions{})
		t.Fatalf("workload guard qualification: %v; native policy status: %+v", err, current.Status)
	}
	deployment, err := admin.AppsV1().Deployments(pool.Namespace).Get(ctx, pool.Deployment, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rv := deployment.ResourceVersion
	if _, _, err = guard.Current(ctx); err != nil {
		t.Fatal(err)
	}
	unchanged, err := admin.AppsV1().Deployments(pool.Namespace).Get(ctx, pool.Deployment, meta.GetOptions{})
	if err != nil || unchanged.ResourceVersion != rv {
		t.Fatal("dry-run altered Deployment", err)
	}
	denied := func(name string, err error) {
		t.Helper()
		var status apierrors.APIStatus
		if !errors.As(err, &status) || status.Status().Details == nil {
			t.Fatalf("%s missing structured admission denial: %v", name, err)
		}
		for _, cause := range status.Status().Details.Causes {
			if cause.Message == "ValidatingAdmissionPolicy '"+plan.Name+"' with binding '"+plan.Name+"' denied request: Asservat private hub namespace requires an installation administrator or a qualified Kubernetes controller operation." {
				return
			}
		}
		t.Fatalf("%s failed outside expected admission policy: %v", name, err)
	}
	create := meta.CreateOptions{DryRun: []string{meta.DryRunAll}}
	update := meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}
	_, err = attacker.AppsV1().Deployments(pool.Namespace).Update(ctx, deployment, update)
	denied("deployment mutation", err)
	pod, err := admin.CoreV1().Pods(pool.Namespace).Get(ctx, podName, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	controllerConfig := rest.CopyConfig(config)
	controllerConfig.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:kube-system:replicaset-controller", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"}}
	controllerAPI, err := kubernetes.NewForConfig(controllerConfig)
	if err != nil {
		t.Fatal(err)
	}
	legitimate := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "controller-dry-run", Namespace: pool.Namespace, Labels: pod.Labels, OwnerReferences: pod.OwnerReferences}, Spec: *pod.Spec.DeepCopy()}
	legitimate.Spec.NodeName = ""
	if _, err = controllerAPI.CoreV1().Pods(pool.Namespace).Create(ctx, legitimate, create); err != nil {
		t.Fatal("reference ReplicaSet controller Pod creation rejected", err)
	}
	for _, account := range []string{pool.ServiceAccount, "default"} {
		forged := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "forged-owner", Namespace: pool.Namespace, Labels: pod.Labels, OwnerReferences: pod.OwnerReferences}, Spec: *pod.Spec.DeepCopy()}
		forged.Spec.NodeName = ""
		forged.Spec.ServiceAccountName = account
		_, err = attacker.CoreV1().Pods(pool.Namespace).Create(ctx, forged, create)
		denied("forged Pod with "+account, err)
	}
	rs := &apps.ReplicaSet{ObjectMeta: meta.ObjectMeta{Name: "forged-owner", OwnerReferences: []meta.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: pool.Deployment, UID: types.UID(pool.DeploymentUID), Controller: ptr.To(true)}}}, Spec: apps.ReplicaSetSpec{Replicas: ptr.To(int32(1)), Selector: deployment.Spec.Selector, Template: deployment.Spec.Template}}
	_, err = attacker.AppsV1().ReplicaSets(pool.Namespace).Create(ctx, rs, create)
	denied("forged ReplicaSet", err)
	_, err = attacker.CoreV1().Secrets(pool.Namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "injected-token", Annotations: map[string]string{"kubernetes.io/service-account.name": pool.ServiceAccount}}, Type: core.SecretTypeServiceAccountToken}, create)
	denied("legacy token injection", err)
	account, err := admin.CoreV1().ServiceAccounts(pool.Namespace).Get(ctx, pool.ServiceAccount, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = attacker.CoreV1().ServiceAccounts(pool.Namespace).Update(ctx, account, update)
	denied("account mutation", err)
	_, err = attacker.CoreV1().ServiceAccounts(pool.Namespace).CreateToken(ctx, pool.ServiceAccount, &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: []string{"synthetic-owner"}, ExpirationSeconds: ptr.To(int64(600))}}, create)
	denied("TokenRequest", err)
	pod.Spec.EphemeralContainers = []core.EphemeralContainer{{EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "injected", Image: pod.Spec.Containers[0].Image, SecurityContext: pod.Spec.Containers[0].SecurityContext}}}
	_, err = attacker.CoreV1().Pods(pool.Namespace).UpdateEphemeralContainers(ctx, pod.Name, pod, update)
	denied("ephemeral process injection", err)
	// A denied CONNECT cannot execute anything. Without admission this request
	// lacks the protocol upgrade needed to start an exec session.
	response := attacker.CoreV1().RESTClient().Post().Namespace(pool.Namespace).Resource("pods").Name(pod.Name).SubResource("exec").Param("command", "true").Param("stdout", "true").Do(ctx)
	denied("exec CONNECT", response.Error())
	if _, err = readonly.CoreV1().Secrets(pool.Namespace).List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(err) {
		t.Fatal("observer may read credentials", err)
	}
	if _, err = readonly.AppsV1().Deployments(pool.Namespace).Update(ctx, deployment, update); !apierrors.IsForbidden(err) {
		t.Fatal("observer may update workload", err)
	}
	if _, err = admin.AppsV1().Deployments(pool.Namespace).Update(ctx, deployment, update); err != nil {
		t.Fatal("installer blocked", err)
	}
	// Force an actual fresh controller-owned Pod after protection is active.
	// The admission policy must preserve ReplicaSet creation, scheduling and
	// kubelet status updates, not merely accept objects that already existed.
	if err = admin.CoreV1().Pods(pool.Namespace).Delete(ctx, pod.Name, meta.DeleteOptions{GracePeriodSeconds: ptr.To(int64(0))}); err != nil {
		t.Fatal(err)
	}
	ready := false
	until = time.Now().Add(20 * time.Second)
	for time.Now().Before(until) {
		pods, e := admin.CoreV1().Pods(pool.Namespace).List(ctx, meta.ListOptions{LabelSelector: "app=owner-discovery"})
		if e != nil {
			t.Fatal(e)
		}
		for _, replacement := range pods.Items {
			if replacement.UID != pod.UID && replacement.DeletionTimestamp == nil {
				for _, condition := range replacement.Status.Conditions {
					if condition.Type == core.PodReady && condition.Status == core.ConditionTrue {
						ready = true
					}
				}
			}
		}
		if ready {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		// Preserve synthetic controller diagnostics before the owned fixture is
		// removed. Never rely on a Ready timeout alone to choose an exception.
		pods, _ := admin.CoreV1().Pods(pool.Namespace).List(ctx, meta.ListOptions{LabelSelector: "app=owner-discovery"})
		if pods != nil {
			for _, p := range pods.Items {
				t.Logf("replacement %s node=%s phase=%s conditions=%+v", p.Name, p.Spec.NodeName, p.Status.Phase, p.Status.Conditions)
			}
		}
		events, _ := admin.CoreV1().Events(pool.Namespace).List(ctx, meta.ListOptions{})
		if events != nil {
			for _, event := range events.Items {
				t.Logf("controller event %s %s: %s", event.InvolvedObject.Kind, event.Reason, event.Message)
			}
		}
		t.Fatal("ordinary controllers could not replace the protected hub Pod")
	}
	advanceBeforeProbe.Store(true)
	if _, _, err = guard.Current(ctx); err != nil {
		t.Fatal("guard failed after controller rollout", err)
	}
	if protected != nil {
		// Both native policies must coexist. Namespace-wide denial must not
		// nondeterministically mask the independently pinned source-policy proof.
		probeConfig := rest.CopyConfig(config)
		probeConfig.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + pool.Namespace + ":owner-config-probe", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + pool.Namespace, "system:authenticated"}}
		sourceProbe, e := kubernetes.NewForConfig(probeConfig)
		if e != nil {
			t.Fatal(e)
		}
		cm, e := admin.CoreV1().ConfigMaps(pool.Namespace).Get(ctx, "owner-pool", meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		for i := 0; i < 16; i++ {
			_, e = sourceProbe.CoreV1().ConfigMaps(pool.Namespace).Update(ctx, cm, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
			var status apierrors.APIStatus
			matched := false
			if errors.As(e, &status) && status.Status().Details != nil {
				for _, cause := range status.Status().Details.Causes {
					if cause.Message == "ValidatingAdmissionPolicy 'asservat-owner-configuration' with binding 'asservat-owner-configuration' denied request: Asservat hub owner configuration administrator is required." {
						matched = true
					}
				}
			}
			if !matched {
				t.Fatalf("independent source proof masked at attempt %d: %v", i, e)
			}
		}
		protected(guard, reader)
		// The nested owner runtime is now stopped. Remove only source admission
		// to prove the namespace exception never grants a persistent write,
		// even when that independent guard is absent.
		exerciseOwnerSourceProbeIsolation(t, ctx, admin, sourceProbe, attacker, pool.Namespace, denied)
	}
	if err = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, plan.Name, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	// A current proof is reused for OwnerProtectionReuse, so loss is observed
	// once that window ends, not immediately.
	until = time.Now().Add(kube.OwnerProtectionReuse + 10*time.Second)
	for _, _, err = guard.Current(ctx); err == nil && time.Now().Before(until); _, _, err = guard.Current(ctx) {
		time.Sleep(time.Second)
	}
	if err == nil {
		t.Fatal("missing workload protection remained current")
	}
	// Negative control proves this is admission enforcement, not ordinary RBAC
	// or another policy rejecting the same unchanged dry-run update.
	until = time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		deployment, err = admin.AppsV1().Deployments(pool.Namespace).Get(ctx, pool.Deployment, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = attacker.AppsV1().Deployments(pool.Namespace).Update(ctx, deployment, update)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("negative control never reached admitted dry-run", err)
	}
	unchanged, err = admin.AppsV1().Deployments(pool.Namespace).Get(ctx, pool.Deployment, meta.GetOptions{})
	if err != nil || unchanged.ResourceVersion != deployment.ResourceVersion {
		t.Fatal("negative control persisted state", err)
	}
	t.Log("native workload guard denied namespace-writer credential/workload/exec injection, preserved real controller replacement and rejected missing protection; dry-runs made no persisted change")
}

func exerciseOwnerSourceProbeIsolation(t *testing.T, ctx context.Context, admin, sourceProbe, attacker kubernetes.Interface, namespace string, denied func(string, error)) {
	t.Helper()
	// Deliberately broader fixture attack rights let admission (rather than
	// RBAC) decide every negative case. Runtime probes retain named get/update.
	role := "source-probe-isolation-test"
	_, err := admin.RbacV1().Roles(namespace).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: role}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps", "secrets"}, Verbs: []string{"get", "create", "update", "delete"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.RbacV1().RoleBindings(namespace).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: role}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: namespace, Name: "owner-config-probe"}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: role}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := admin.CoreV1().ConfigMaps(namespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "unrelated-source"}, Data: map[string]string{"fixture": "synthetic"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := admin.CoreV1().Secrets(namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "source-probe-synthetic"}, Data: map[string][]byte{"fixture": []byte("synthetic")}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, "asservat-owner-configuration", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, binding.Name, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	cm, err := admin.CoreV1().ConfigMaps(namespace).Get(ctx, "owner-pool", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	update := meta.UpdateOptions{DryRun: []string{meta.DryRunAll}, FieldValidation: "Strict"}
	until := time.Now().Add(8 * time.Second)
	for time.Now().Before(until) {
		_, err = sourceProbe.CoreV1().ConfigMaps(namespace).Update(ctx, cm, update)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("isolated named dry-run could not pass namespace policy", err)
	}
	changed := cm.DeepCopy()
	changed.Data["fixture-attempt"] = "must-never-persist"
	_, err = sourceProbe.CoreV1().ConfigMaps(namespace).Update(ctx, changed, meta.UpdateOptions{})
	denied("source probe real update without source guard", err)
	_, err = attacker.CoreV1().ConfigMaps(namespace).Update(ctx, cm, update)
	denied("other actor dry-run source update", err)
	_, err = sourceProbe.CoreV1().ConfigMaps(namespace).Update(ctx, other, update)
	denied("source probe other ConfigMap dry-run", err)
	_, err = sourceProbe.CoreV1().Secrets(namespace).Update(ctx, secret, update)
	denied("source probe Secret dry-run", err)
	create := &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: cm.Name}}
	_, err = sourceProbe.CoreV1().ConfigMaps(namespace).Create(ctx, create, meta.CreateOptions{DryRun: []string{meta.DryRunAll}})
	denied("source probe create dry-run", err)
	err = sourceProbe.CoreV1().ConfigMaps(namespace).Delete(ctx, cm.Name, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}})
	denied("source probe delete dry-run", err)
	current, err := admin.CoreV1().ConfigMaps(namespace).Get(ctx, cm.Name, meta.GetOptions{})
	if err != nil || current.ResourceVersion != cm.ResourceVersion {
		t.Fatal("probe scope tests persisted configuration", err)
	}
	// Recreate for the enclosing source test's own missing-binding control.
	// This is a new UID, deliberately not accepted as the original guard.
	_, err = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, &admission.ValidatingAdmissionPolicyBinding{ObjectMeta: meta.ObjectMeta{Name: binding.Name}, Spec: binding.Spec}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("source probe exception permits only the named account's ConfigMap dry-run UPDATE; real writes, other actors/objects, Secrets and create/delete remain denied without the source guard")
}
