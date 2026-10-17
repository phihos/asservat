package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	auth "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	coordination "k8s.io/api/coordination/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The mounted worker must coexist with the real namespace policy. No account
// is added to installation administrators to allow ordinary scheduling work.
func protectHubWorkerNamespace(t *testing.T, ctx context.Context, api kubernetes.Interface, kc *rest.Config, owner contracts.OwnerConfiguration, lease *coordination.Lease) {
	t.Helper()
	ns := owner.Namespace.Name
	who, err := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Broad attack rights are fixture-only: the actual leader keeps named
	// get/update and all forbidden operations must reach native admission.
	actor := "configuration-worker-attack"
	_, err = api.CoreV1().ServiceAccounts(ns).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: actor}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.RbacV1().Roles(ns).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: actor}, Rules: []rbac.PolicyRule{{APIGroups: []string{"", "coordination.k8s.io"}, Resources: []string{"configmaps", "secrets", "serviceaccounts/token", "leases"}, Verbs: []string{"get", "create", "update", "delete"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.RbacV1().RoleBindings(ns).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: actor}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: actor, Namespace: ns}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: actor}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	client := func(name string) kubernetes.Interface {
		t.Helper()
		token, e := api.CoreV1().ServiceAccounts(ns).CreateToken(ctx, name, &auth.TokenRequest{}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		c, e := kubernetes.NewForConfig(&rest.Config{Host: kc.Host, BearerToken: token.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: kc.CAData, CAFile: kc.CAFile}})
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	attacker, leader := client(actor), client("configuration-worker-leader")
	plan := cfg.OwnerWorkloadAdministration{SchedulingLeases: []cfg.OwnerSchedulingLease{{Lease: lease.Name, ServiceAccount: "configuration-worker-leader"}}, Name: "configuration-worker-namespace", Deployment: owner.Deployment.Name, DeploymentUID: owner.Deployment.UID, ControlNamespace: cfg.NamespaceRef{Name: ns, UID: owner.Namespace.UID}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}, ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: "fleet", ServiceAccount: "configuration-worker-probe"}, {ConfigMap: "owner", ServiceAccount: "configuration-worker-probe"}}}
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
	expected := "ValidatingAdmissionPolicy '" + plan.Name + "' with binding '" + plan.Name + "' denied request: Asservat private hub namespace requires an installation administrator or a qualified Kubernetes controller operation."
	until := time.Now().Add(10 * time.Second)
	active := false
	for time.Now().Before(until) {
		_, err = attacker.CoordinationV1().Leases(ns).Update(ctx, lease, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}})
		var status apierrors.APIStatus
		if errors.As(err, &status) && status.Status().Details != nil {
			for _, cause := range status.Status().Details.Causes {
				if cause.Message == expected {
					active = true
				}
			}
		}
		if active {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !active {
		t.Fatal("private namespace guard not enforcing", err)
	}
	changed := lease.DeepCopy()
	changed.Annotations = map[string]string{"fixture": "bounded-scheduling"}
	lease, err = leader.CoordinationV1().Leases(ns).Update(ctx, changed, meta.UpdateOptions{})
	if err != nil {
		t.Fatal("scoped scheduling update blocked by private namespace guard", err)
	}
	denied := func(label string, err error) {
		t.Helper()
		var status apierrors.APIStatus
		if errors.As(err, &status) && status.Status().Details != nil {
			for _, cause := range status.Status().Details.Causes {
				if cause.Message == expected {
					return
				}
			}
		}
		t.Fatalf("%s: expected namespace admission denial, got %v", label, err)
	}
	access := func(verb, group, resource, name string) bool {
		t.Helper()
		review, e := leader.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorization.SelfSubjectAccessReview{Spec: authorization.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorization.ResourceAttributes{Namespace: ns, Verb: verb, Group: group, Resource: resource, Name: name}}}, meta.CreateOptions{})
		if e != nil || review.Status.EvaluationError != "" {
			t.Fatal("leader RBAC observation", e)
		}
		return review.Status.Allowed && !review.Status.Denied
	}
	for _, v := range []struct{ verb, group, resource, name string }{{"create", "coordination.k8s.io", "leases", ""}, {"delete", "coordination.k8s.io", "leases", lease.Name}, {"update", "coordination.k8s.io", "leases", "unrelated"}, {"get", "", "secrets", "synthetic"}} {
		if access(v.verb, v.group, v.resource, v.name) {
			t.Fatal("actual leader role is broader than scheduling", v)
		}
	}
	other, err := api.CoordinationV1().Leases(ns).Create(ctx, &coordination.Lease{ObjectMeta: meta.ObjectMeta{Name: "unrelated"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm, err := api.CoreV1().ConfigMaps(ns).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: lease.Name}, Data: map[string]string{"fixture": "synthetic"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := api.CoreV1().Secrets(ns).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: lease.Name}, Data: map[string][]byte{"fixture": []byte("synthetic")}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Temporarily give the allowed account broad fixture-only attack rights.
	// This forces forbidden requests past RBAC to test the admission scope.
	extra := actor + "-leader"
	_, err = api.RbacV1().RoleBindings(ns).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: extra}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "configuration-worker-leader", Namespace: ns}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: actor}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	until = time.Now().Add(5 * time.Second)
	for !access("update", "coordination.k8s.io", "leases", other.Name) && time.Now().Before(until) {
		time.Sleep(50 * time.Millisecond)
	}
	if !access("update", "coordination.k8s.io", "leases", other.Name) {
		t.Fatal("fixture attack role not active")
	}
	update := meta.UpdateOptions{DryRun: []string{meta.DryRunAll}, FieldValidation: "Strict"}
	_, err = attacker.CoordinationV1().Leases(ns).Update(ctx, lease, update)
	denied("other scheduling actor", err)
	_, err = leader.CoordinationV1().Leases(ns).Update(ctx, other, update)
	denied("unlisted Lease", err)
	_, err = leader.CoordinationV1().Leases(ns).Create(ctx, &coordination.Lease{ObjectMeta: meta.ObjectMeta{Name: lease.Name}}, meta.CreateOptions{DryRun: []string{meta.DryRunAll}})
	denied("Lease creation", err)
	err = leader.CoordinationV1().Leases(ns).Delete(ctx, lease.Name, meta.DeleteOptions{DryRun: []string{meta.DryRunAll}})
	denied("Lease deletion", err)
	_, err = leader.CoreV1().ConfigMaps(ns).Update(ctx, cm, update)
	denied("same name ConfigMap", err)
	_, err = leader.CoreV1().Secrets(ns).Update(ctx, secret, update)
	denied("same name Secret", err)
	_, err = leader.CoreV1().ServiceAccounts(ns).CreateToken(ctx, "configuration-worker-leader", &auth.TokenRequest{}, meta.CreateOptions{})
	denied("token minting", err)
	unchanged, err := api.CoordinationV1().Leases(ns).Get(ctx, lease.Name, meta.GetOptions{})
	if err != nil || unchanged.UID != lease.UID || unchanged.ResourceVersion != lease.ResourceVersion {
		t.Fatal("negative tests mutated scheduling object", err)
	}
	if err = api.RbacV1().RoleBindings(ns).Delete(ctx, extra, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	until = time.Now().Add(5 * time.Second)
	for access("update", "coordination.k8s.io", "leases", other.Name) && time.Now().Before(until) {
		time.Sleep(50 * time.Millisecond)
	}
	if access("update", "coordination.k8s.io", "leases", other.Name) || access("get", "", "secrets", secret.Name) {
		t.Fatal("fixture attack role still active before runtime")
	}
	t.Log("private namespace scheduling: exact non-administrator Lease update allowed; actual RBAC is narrow; broader fixture rights cannot create/delete Leases, update other objects or mint tokens; runtime starts only after extra rights are removed")
}
