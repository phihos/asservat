package kubernetes

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// This focused qualification uses a fresh caller-owned Kind API, no SQL,
// evidence or product credentials. Probes have fixture-only metadata write
// rights to exercise real admission denials. Both policies protect the same key.
func TestCapacityNamespaceGuardsOnSameAPINative(t *testing.T) {
	path := os.Getenv("ASSERVAT_CAPACITY_GUARD_KUBECONFIG")
	if path == "" {
		t.Skip("requires a fresh owned API through ASSERVAT_CAPACITY_GUARD_KUBECONFIG")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	who, err := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil || who.Status.UserInfo.Username == "" {
		t.Fatal("original native administrator", err)
	}
	guards := make([]*CapacityNamespaceGuard, 0, 2)
	for _, name := range []string{"capacity-a", "capacity-b"} {
		ns, err := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal("fresh probe namespace", err)
		}
		account, err := api.CoreV1().ServiceAccounts(name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "probe"}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = api.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{name}, Verbs: []string{"get", "update"}}, {APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"create"}}}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = api.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "probe", Namespace: name}}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		control := cfg.NamespaceRef{Name: name, UID: string(ns.UID)}
		plan := cfg.CapacityNamespaceAdministration{Name: name, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}, Keys: []string{"team"}, ProbeNamespace: control, ProbeAccount: cfg.NamespaceRef{Name: account.Name, UID: string(account.UID)}}
		policy, binding, err := CapacityNamespaceAdmission(plan)
		if err != nil {
			t.Fatal(err)
		}
		policy, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		binding, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		seconds := int64(600)
		token, err := api.CoreV1().ServiceAccounts(name).CreateToken(ctx, "probe", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: &seconds}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		anonymous := rest.AnonymousClientConfig(config)
		anonymous.BearerToken = token.Status.Token
		probe, err := NewPermissionClient(anonymous, permissionCluster, control, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		observer, err := NewPermissionClient(config, permissionCluster, control, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		guard, err := NewCapacityNamespaceGuard(observer, probe, plan, GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion})
		if err != nil {
			t.Fatal(err)
		}
		guards = append(guards, guard)
		if len(guards) == 1 {
			for end := time.Now().Add(15 * time.Second); ; time.Sleep(100 * time.Millisecond) {
				if _, err = guard.CapacityNamespaceProtection(ctx); err == nil {
					break
				}
				if time.Now().After(end) {
					t.Fatal("first real guard never became enforceable", err)
				}
			}
			t.Log("first independent real namespace guard proved")
		}
	}
	// Print only fixed policy names and fixed synthetic denial text. A positive
	// independent proof must be available for each guard once both are present.
	for _, guard := range guards {
		var last error
		for end := time.Now().Add(5 * time.Second); ; time.Sleep(100 * time.Millisecond) {
			if _, last = guard.CapacityNamespaceProtection(ctx); last == nil || time.Now().After(end) {
				break
			}
		}
		ns, err := api.CoreV1().Namespaces().Get(ctx, guard.guard.namespace.Name, meta.GetOptions{})
		if err != nil || ns.Labels["team"] != "" {
			t.Fatal("denial proof persisted selector metadata", err)
		}
		ns.Labels["team"] = "synthetic-denial-probe"
		// Use the same independent probe transport already validated by the guard.
		response := guard.guard.probe.api.Put().AbsPath("/api/v1/namespaces/"+ns.Name).Param("dryRun", "All").Body(ns).Do(ctx)
		var status apierrors.APIStatus
		if errors.As(response.Error(), &status) && status.Status().Details != nil {
			for _, cause := range status.Status().Details.Causes {
				t.Logf("probe=%s denial-cause=%s", guard.guard.name, cause.Message)
			}
		}
		if last != nil {
			t.Error("independent namespace guard cannot prove enforcement with both policies", guard.guard.name, last)
		}
		for _, dryRun := range []string{"", "false", "null"} {
			request := guard.guard.probe.api.Put().AbsPath("/api/v1/namespaces/" + ns.Name).Body(ns)
			if dryRun != "" {
				request.Param("dryRun", dryRun)
			}
			err := request.Do(ctx).Error()
			if err == nil {
				t.Error("persistent or invalid dry-run namespace update was allowed", dryRun)
			}
			if dryRun == "" && capacityExactDenial(err, "capacity-a", "", "namespaces", capacityNamespaceDenial) != nil && capacityExactDenial(err, "capacity-b", "", "namespaces", capacityNamespaceDenial) != nil {
				t.Fatal("real namespace update did not reach the actual metadata guards", err)
			}
		}
		create := &core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: ns.Name + "-create-refused", Labels: map[string]string{"team": "synthetic-protected"}}}
		_, createErr := guard.guard.probe.proofPost(ctx, "/api/v1/namespaces", create, nil)
		if capacityExactDenial(createErr, "capacity-a", "", "namespaces", capacityNamespaceDenial) != nil && capacityExactDenial(createErr, "capacity-b", "", "namespaces", capacityNamespaceDenial) != nil {
			t.Fatal("real namespace CREATE did not remain protected", createErr)
		}
		if _, err := api.CoreV1().Namespaces().Get(ctx, create.Name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatal("refused namespace CREATE persisted", err)
		}
		// Removing the exact binding must make this probe's dry-run succeed,
		// even while the other global guard remains installed. Its proof fails.
		binding, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, guard.guard.name, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, binding.Name, meta.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		for end := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
			err = guard.guard.probe.api.Put().AbsPath("/api/v1/namespaces/"+ns.Name).Param("dryRun", "All").Body(ns).Do(ctx).Error()
			if err == nil || time.Now().After(end) {
				break
			}
		}
		if err != nil {
			t.Fatal("foreign global guard hid the missing target binding", err)
		}
		if _, err := guard.CapacityNamespaceProtection(ctx); err == nil {
			t.Fatal("missing own binding borrowed another guard's denial")
		}
		other := "capacity-a"
		if guard.guard.name == other {
			other = "capacity-b"
		}
		err = guard.guard.probe.api.Put().AbsPath("/api/v1/namespaces/" + ns.Name).Body(ns).Do(ctx).Error()
		if capacityExactDenial(err, other, "", "namespaces", capacityNamespaceDenial) != nil {
			t.Fatal("foreign guard allowed a persistent update without the target binding", err)
		}
		binding.ObjectMeta = meta.ObjectMeta{Name: binding.Name}
		if _, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		current, err := api.CoreV1().Namespaces().Get(ctx, ns.Name, meta.GetOptions{})
		if err != nil || current.Labels["team"] != "" {
			t.Fatal("namespace probe or refused write persisted metadata", err)
		}
	}
	testWorkloadGuardsOnSameAPI(t, ctx, api, guards)
}

func testWorkloadGuardsOnSameAPI(t *testing.T, ctx context.Context, api kubernetes.Interface, namespaces []*CapacityNamespaceGuard) {
	t.Helper()
	var guards []*WorkloadGuard
	for _, namespace := range namespaces {
		s := namespace.guard
		name := s.name + "-workload"
		_, err := api.RbacV1().Roles(s.namespace.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "workload-probe"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create", "update"}}}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = api.RbacV1().RoleBindings(s.namespace.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "workload-probe"}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "workload-probe"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: s.account.Name, Namespace: s.namespace.Name}}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		plan := cfg.WorkloadAdministration{Name: name, Administrators: s.administrators, LabelKeys: []string{"team"}, ProbeNamespace: s.namespace, ProbeAccount: s.account}
		policy, binding, err := WorkloadAdmission(plan)
		if err != nil {
			t.Fatal(err)
		}
		policy, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		binding, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		guard, err := NewWorkloadGuard(s.observer, s.probe, plan, GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion})
		if err != nil {
			t.Fatal(err)
		}
		guards = append(guards, guard)
	}
	for _, guard := range guards {
		s := guard.guard
		for end := time.Now().Add(15 * time.Second); ; time.Sleep(100 * time.Millisecond) {
			if _, err := guard.WorkloadGuardProof(ctx); err == nil {
				break
			} else if time.Now().After(end) {
				t.Fatal("both real workload guards must prove independently", s.name, err)
			}
		}
		labels := map[string]string{"app": "probe"}
		body := &apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta.ObjectMeta{Name: "metadata-probe", Namespace: s.namespace.Name, Labels: map[string]string{"team": "synthetic-protected"}}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(0)), Selector: &meta.LabelSelector{MatchLabels: labels}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{Containers: []core.Container{{Name: "probe", Image: "registry.invalid/probe:0"}}}}}}
		path := "/apis/apps/v1/namespaces/" + s.namespace.Name + "/deployments"
		for _, dryRun := range []string{"", "false", "null"} {
			query := map[string]string{}
			if dryRun != "" {
				query["dryRun"] = dryRun
			}
			_, err := s.probe.proofPost(ctx, path, body, query)
			if err == nil {
				t.Fatal("persistent or invalid dry-run workload CREATE was allowed", dryRun)
			}
			if dryRun == "" && capacityExactDenial(err, "capacity-a-workload", "apps", "deployments", workloadMetadataDenial) != nil && capacityExactDenial(err, "capacity-b-workload", "apps", "deployments", workloadMetadataDenial) != nil {
				t.Fatal("real workload CREATE did not reach the metadata guards", err)
			}
		}
		original := body.DeepCopy()
		original.Name = "original-metadata"
		original.Labels["team"] = "before"
		original, err := api.AppsV1().Deployments(s.namespace.Name).Create(ctx, original, meta.CreateOptions{})
		if err != nil {
			t.Fatal("administrator's original inert workload", err)
		}
		original.Labels["team"] = "after"
		err = s.probe.api.Put().AbsPath(path + "/" + original.Name).Body(original).Do(ctx).Error()
		if capacityExactDenial(err, "capacity-a-workload", "apps", "deployments", workloadMetadataDenial) != nil && capacityExactDenial(err, "capacity-b-workload", "apps", "deployments", workloadMetadataDenial) != nil {
			t.Fatal("real workload UPDATE did not remain protected", err)
		}
		binding, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, s.name, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, s.name, meta.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		for end := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
			_, err = s.probe.proofPost(ctx, path, body, map[string]string{"dryRun": "All"})
			if err == nil || time.Now().After(end) {
				break
			}
		}
		if err != nil {
			t.Fatal("foreign workload guard hid a missing own binding", err)
		}
		if _, err := guard.WorkloadGuardProof(ctx); err == nil {
			t.Fatal("workload proof borrowed another guard's denial")
		}
		other := "capacity-a-workload"
		if s.name == other {
			other = "capacity-b-workload"
		}
		_, err = s.probe.proofPost(ctx, path, body, nil)
		if capacityExactDenial(err, other, "apps", "deployments", workloadMetadataDenial) != nil {
			t.Fatal("foreign workload guard allowed persistent CREATE without target binding", err)
		}
		binding.ObjectMeta = meta.ObjectMeta{Name: s.name}
		if _, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err = api.AppsV1().Deployments(s.namespace.Name).Get(ctx, body.Name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatal("workload probe or refused write persisted", err)
		}
		current, err := api.AppsV1().Deployments(s.namespace.Name).Get(ctx, original.Name, meta.GetOptions{})
		if err != nil || current.Labels["team"] != "before" {
			t.Fatal("refused workload UPDATE persisted", err)
		}
		t.Log("independent workload guard and missing-own-binding refusal passed", s.name)
	}
}
