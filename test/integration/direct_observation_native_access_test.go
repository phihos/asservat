package integration

import (
	"context"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	auth "k8s.io/api/authentication/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

func (x *directNativeCluster) installAccess(t *testing.T, ctx context.Context, modes []string, installation string) {
	t.Helper()
	ns := x.namespace.Name
	for _, mode := range append(append([]string{}, modes...), "setup-observer", "probe") {
		name := ns + "-" + mode
		clusterRules := []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns}, Verbs: []string{"get"}}, {APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{ns, ns + "-source", ns + "-capacity"}, Verbs: []string{"get"}}}
		rules := []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"services", "serviceaccounts", "configmaps"}, ResourceNames: []string{"owner", "hwork", "regional", "probe", "setup-observer", "connector-identity"}, Verbs: []string{"get"}}, {APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"owner", "hwork", "regional"}, Verbs: []string{"get"}}, {APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}, {APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: []string{"get"}}, {APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"list"}}}
		if mode == "owner" || mode == "hwork" {
			// ADR-227: the owner observation boundary reads the release record
			// by exact name, as the product owner/hub-worker RBAC grants.
			rules = append(rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{contracts.ReleaseRecordName(installation)}, Verbs: []string{"get"}})
		}
		if mode == "owner" || mode == "regional" {
			clusterRules = append(clusterRules, rbac.PolicyRule{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}})
		}
		if mode == "regional" {
			// These are the existing four read-only capacity metadata purposes.
			// LIST discovers candidates only; later reads and authority remain exact.
			clusterRules = append(clusterRules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get", "list"}}, rbac.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}}, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}})
			// ADR-168: exactly the one cluster credential Secret, read and CAS.
			rules = append(rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"cluster-credential"}, Verbs: []string{"get", "update"}})
			if x.product {
				// The product process is its own independent probe account; its
				// dry-run updates must be denied by the guards, not by RBAC.
				clusterRules = append(clusterRules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns}, Verbs: []string{"update"}}, rbac.PolicyRule{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"selfsubjectreviews"}, Verbs: []string{"create"}}, rbac.PolicyRule{APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews"}, Verbs: []string{"create"}})
				rules = append(rules, rbac.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{x.plan.Deployment}, Verbs: []string{"update"}}, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"connector-identity"}, Verbs: []string{"update"}})
			}
		}
		if mode == "probe" {
			clusterRules = []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns}, Verbs: []string{"get", "update"}}, {APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"selfsubjectreviews"}, Verbs: []string{"create"}}, {APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews"}, Verbs: []string{"create"}}}
			rules = []rbac.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{x.plan.Deployment}, Verbs: []string{"get", "update"}}, {APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"connector-identity"}, Verbs: []string{"get", "update"}}}
		}
		if _, e := x.api.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: clusterRules}, meta.CreateOptions{}); e != nil {
			t.Fatal("native fixed cluster role", e)
		}
		if _, e := x.api.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: mode}}}, meta.CreateOptions{}); e != nil {
			t.Fatal("native fixed cluster binding", e)
		}
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for _, e := range []error{x.api.RbacV1().ClusterRoleBindings().Delete(c, name, meta.DeleteOptions{}), x.api.RbacV1().ClusterRoles().Delete(c, name, meta.DeleteOptions{})} {
				if e != nil && !apierrors.IsNotFound(e) {
					t.Error("native fixed RBAC cleanup", e)
				}
			}
		})
		if _, e := x.api.RbacV1().Roles(ns).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: mode}, Rules: rules}, meta.CreateOptions{}); e != nil {
			t.Fatal("native fixed namespace role", e)
		}
		if _, e := x.api.RbacV1().RoleBindings(ns).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: mode}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: mode}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: mode}}}, meta.CreateOptions{}); e != nil {
			t.Fatal("native fixed namespace binding", e)
		}
	}
	probe := "probe"
	if x.product {
		probe = "regional" // the product process is its own probe account
	}
	token, e := x.api.CoreV1().ServiceAccounts(ns).CreateToken(ctx, probe, &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(900))}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal("native independent probe token", e)
	}
	x.probeToken = token.Status.Token
}

func (x *directNativeCluster) clients(t *testing.T) (*kube.PermissionClient, *kube.PermissionClient) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	token, e := x.api.CoreV1().ServiceAccounts(x.namespace.Name).CreateToken(ctx, "setup-observer", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(900))}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal("setup observer token", e)
	}
	makeClient := func(token string) *kube.PermissionClient {
		c := &rest.Config{Host: x.config.Host, BearerToken: token, TLSClientConfig: rest.TLSClientConfig{CAData: x.config.CAData, CAFile: x.config.CAFile}}
		out, e := kube.NewPermissionClient(c, x.id, x.plan.ControlNamespace, time.Now)
		if e != nil {
			t.Fatal("native setup reader", e)
		}
		return out
	}
	return makeClient(token.Status.Token), makeClient(x.probeToken)
}

func (x *directNativeCluster) baseInput(t *testing.T, mode string, until time.Time) Input {
	t.Helper()
	ca := x.config.CAData
	if len(ca) == 0 {
		t.Fatal("fixture API CA bytes not retained")
	}
	return Input{Format: "observation-native-fixture/v1", Mode: mode, PodUID: string(x.pods[mode].UID), Until: until, API: API{Host: "https://kubernetes.default.svc", CA: ca, ClusterID: x.id, Control: x.plan.ControlNamespace, ObserverTokenFile: "/fixture/observer.token", ProbeTokenFile: "/fixture/probe.token", Workload: x.plan, WorkloadPin: x.guard}, OwnerTokenFile: "/fixture/owner.token", CallerTokenFile: "/fixture/caller.token", ConnectorTokenFile: "/fixture/connector.token"}
}
