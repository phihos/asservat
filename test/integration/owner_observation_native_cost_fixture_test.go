package integration

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

type ownerObservationNativeCostFixture struct {
	pool                      value.OwnerPool
	pin                       value.OwnerObservationPin
	pod                       core.Pod
	replica                   string
	config                    *rest.Config
	observerToken, probeToken string
	plan                      cfg.OwnerWorkloadAdministration
	guardPin                  kube.GuardPin
	counter                   *ownerObservationCostCounter
}

func newOwnerObservationNativeCostFixture(t *testing.T, ctx context.Context, f fixture) *ownerObservationNativeCostFixture {
	t.Helper()
	config, e := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if e != nil {
		t.Fatal("owned API config", e)
	}
	admin, e := kubernetes.NewForConfig(config)
	if e != nil {
		t.Fatal(e)
	}
	sample, e := admin.CoreV1().Pods(f.Clusters[0].Pod.Namespace).Get(ctx, f.Clusters[0].Pod.Name, meta.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(sample.Spec.Containers[0].Image, "@sha256:")
	if len(parts) != 2 {
		t.Fatal("original fixture image is not digest pinned")
	}
	digest, e := hex.DecodeString(parts[1])
	if e != nil || len(digest) != 32 {
		t.Fatal("original fixture image digest")
	}
	var image artifact.Digest
	copy(image[:], digest)
	id := custodyID()
	name := "owner-cost-" + id[len(id)-12:]
	ns, e := admin.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		if e := admin.CoreV1().Namespaces().Delete(c, name, meta.DeleteOptions{}); e != nil && !apierrors.IsNotFound(e) {
			t.Error("owned cost namespace cleanup", e)
		}
	})
	accounts := map[string]*core.ServiceAccount{}
	for _, n := range []string{"owner", "observer", "probe"} {
		a, e := admin.CoreV1().ServiceAccounts(name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: n}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		accounts[n] = a
	}
	labels := map[string]string{"app": name}
	spec := core.PodSpec{ServiceAccountName: "owner", AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), RestartPolicy: core.RestartPolicyAlways, TerminationGracePeriodSeconds: ptr.To(int64(1)), SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Containers: []core.Container{{Name: "fixture", Image: sample.Spec.Containers[0].Image, ImagePullPolicy: core.PullIfNotPresent, SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}, Resources: core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("5m"), core.ResourceMemory: resource.MustParse("8Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("50m"), core.ResourceMemory: resource.MustParse("32Mi")}}}}, Tolerations: []core.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}, {Key: "node.kubernetes.io/unreachable", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}}}
	deployment, e := admin.AppsV1().Deployments(name).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "owner"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Selector: &meta.LabelSelector{MatchLabels: labels}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: spec}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	ports := []core.ServicePort{{Name: "owner", Port: 9443, TargetPort: intstr.FromInt(9443), Protocol: core.ProtocolTCP}, {Name: "observation", Port: 9444, TargetPort: intstr.FromInt(9444), Protocol: core.ProtocolTCP}, {Name: "public", Port: 9445, TargetPort: intstr.FromInt(9445), Protocol: core.ProtocolTCP}}
	service, e := admin.CoreV1().Services(name).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: "owner"}, Spec: core.ServiceSpec{ClusterIP: core.ClusterIPNone, Selector: labels, Ports: ports}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	x := &ownerObservationNativeCostFixture{config: config, counter: &ownerObservationCostCounter{}, pool: value.OwnerPool{InstallationID: custodyID(), ClusterID: custodyID(), IssuerEpoch: custodyID(), Namespace: name, NamespaceUID: string(ns.UID), Service: "owner", ServiceUID: string(service.UID), Deployment: "owner", DeploymentUID: string(deployment.UID), ServiceAccount: "owner", AccountUID: string(accounts["owner"].UID), Port: 9443, NativePort: 9444, NativeBootstrap: value.OwnerBootstrapProfile, NativeCandidateLimit: 17}}
	who, e := admin.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	x.plan = cfg.OwnerWorkloadAdministration{Name: name, ControlNamespace: cfg.NamespaceRef{Name: name, UID: string(ns.UID)}, Deployment: "owner", DeploymentUID: string(deployment.UID), Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}
	clusterRules := []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{name}, Verbs: []string{"get"}}, {APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{name}, Verbs: []string{"get"}}}
	if _, e = admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: clusterRules}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		for _, e := range []error{admin.RbacV1().ClusterRoleBindings().Delete(c, name, meta.DeleteOptions{}), admin.RbacV1().ClusterRoles().Delete(c, name, meta.DeleteOptions{})} {
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("owned observer RBAC cleanup", e)
			}
		}
	})
	if _, e = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "observer", Namespace: name}}}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	for _, account := range []string{"observer", "probe"} {
		rules := []rbac.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"owner"}, Verbs: []string{"get", "update"}}}
		if account == "observer" {
			rules = []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"services", "serviceaccounts"}, ResourceNames: []string{"owner"}, Verbs: []string{"get"}}, {APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}, {APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: []string{"get"}}, {APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"owner"}, Verbs: []string{"get"}}, {APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"list"}}}
		}
		if _, e = admin.RbacV1().Roles(name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: account}, Rules: rules}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e = admin.RbacV1().RoleBindings(name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: account}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: account}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: account, Namespace: name}}}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		token, e := admin.CoreV1().ServiceAccounts(name).CreateToken(ctx, account, &auth.TokenRequest{}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		if account == "observer" {
			x.observerToken = token.Status.Token
		} else {
			x.probeToken = token.Status.Token
		}
	}
	policy, binding, e := kube.OwnerWorkloadAdmission(x.plan)
	if e != nil {
		t.Fatal(e)
	}
	policy, e = admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		for _, e := range []error{admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(c, name, meta.DeleteOptions{}), admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(c, name, meta.DeleteOptions{})} {
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("owned guard cleanup", e)
			}
		}
	})
	binding, e = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	x.guardPin = kube.GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion}
	// Native controller readiness is setup only, outside all timed admissions.
	for ctx.Err() == nil {
		list, e := admin.CoreV1().Pods(name).List(ctx, meta.ListOptions{LabelSelector: "app=" + name})
		if e != nil {
			t.Fatal(e)
		}
		if len(list.Items) == 1 && list.Items[0].DeletionTimestamp == nil {
			p := list.Items[0]
			ready := false
			for _, v := range p.Status.Conditions {
				ready = ready || v.Type == core.PodReady && v.Status == core.ConditionTrue
			}
			if ready && p.Status.Phase == core.PodRunning {
				x.pod = p
				break
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	if x.pod.UID == "" {
		t.Fatal("actual protected owner did not become Ready")
	}
	deployment, e = admin.AppsV1().Deployments(name).Get(ctx, "owner", meta.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	template, e := kube.ConnectorAPITemplateDigest(deployment.Spec.Template)
	if e != nil {
		t.Fatal("original native template", e)
	}
	for _, ref := range x.pod.OwnerReferences {
		if ref.Kind == "ReplicaSet" && ref.Controller != nil && *ref.Controller {
			x.replica = string(ref.UID)
		}
	}
	if x.replica == "" {
		t.Fatal("original ReplicaSet missing")
	}
	_, guard := x.readers(t)
	var protection artifact.Digest
	for until := time.Now().Add(15 * time.Second); time.Now().Before(until); {
		protection, _, e = guard.Current(ctx)
		if e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("guard qualification cancelled")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if e != nil {
		t.Fatal("native guard did not qualify", e)
	}
	x.pin = value.OwnerObservationPin{RootID: custodyID(), SourceUID: custodyID(), Pool: x.pool, TemplateDigest: template, ImageDigest: image, ProtectionDigest: protection}
	return x
}
func (x *ownerObservationNativeCostFixture) readers(t *testing.T) (*kube.PermissionClient, *kube.OwnerWorkloadProtection) {
	t.Helper()
	makeClient := func(token string, probe bool) *kube.PermissionClient {
		c := &rest.Config{Host: x.config.Host, BearerToken: token, TLSClientConfig: rest.TLSClientConfig{CAData: x.config.CAData, CAFile: x.config.CAFile}, WrapTransport: x.counter.wrap(probe)}
		out, e := kube.NewPermissionClient(c, x.pool.ClusterID, x.plan.ControlNamespace, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	observer, probe := makeClient(x.observerToken, false), makeClient(x.probeToken, true)
	guard, e := kube.NewOwnerWorkloadProtection(observer, probe, x.plan, x.guardPin)
	if e != nil {
		t.Fatal(e)
	}
	return observer, guard
}
