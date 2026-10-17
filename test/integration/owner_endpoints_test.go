package integration

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	app "asservat.local/asservat/internal/application/fleet"
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

// This tests Kubernetes controller output and RBAC, not a running hub owner or
// production issuer. The isolated pause Pod never serves evidence or TLS.
func TestOwnerEndpointsWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run make context-integration for owned Kubernetes")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if json.Unmarshal(b, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("fixtures missing")
	}
	clear(b)
	ctx, end := context.WithTimeout(context.Background(), 90*time.Second)
	defer end()
	config, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	sample, err := admin.CoreV1().Pods(f.Clusters[0].Pod.Namespace).Get(ctx, f.Clusters[0].Pod.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ns, err := admin.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "owner-discovery", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sa, err := admin.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "owner"}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ownerListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ownerListener.Close()
	ownerPort := ownerListener.Addr().(*net.TCPAddr).Port
	labels := map[string]string{"app": "owner-discovery"}
	deployment, err := admin.AppsV1().Deployments(ns.Name).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "owner"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Selector: &meta.LabelSelector{MatchLabels: labels}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{ServiceAccountName: sa.Name, AutomountServiceAccountToken: ptr.To(false), SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Containers: []core.Container{{Name: "fixture", Image: sample.Spec.Containers[0].Image, ImagePullPolicy: core.PullIfNotPresent, SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}, Resources: core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("5m"), core.ResourceMemory: resource.MustParse("8Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("50m"), core.ResourceMemory: resource.MustParse("32Mi")}}}}}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := admin.CoreV1().Services(ns.Name).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: "owner"}, Spec: core.ServiceSpec{ClusterIP: core.ClusterIPNone, Type: core.ServiceTypeClusterIP, Selector: labels, Ports: []core.ServicePort{{Name: "owner-control", Port: int32(ownerPort), TargetPort: intstr.FromInt(ownerPort), Protocol: core.ProtocolTCP}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pool := value.OwnerPool{InstallationID: custodyID(), ClusterID: custodyID(), IssuerEpoch: custodyID(), Namespace: ns.Name, NamespaceUID: string(ns.UID), Service: service.Name, ServiceUID: string(service.UID), Deployment: deployment.Name, DeploymentUID: string(deployment.UID), ServiceAccount: sa.Name, AccountUID: string(sa.UID), Port: ownerPort}
	_, err = admin.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "discovery"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	token, err := admin.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, "discovery", &auth.TokenRequest{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	limited := &rest.Config{Host: config.Host, BearerToken: token.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: config.CAData, CAFile: config.CAFile}}
	client, err := kube.NewPermissionClient(limited, pool.ClusterID, cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := kube.NewOwnerEndpoints(client, pool)
	if err != nil {
		t.Fatal(err)
	}
	binding := value.OwnerBinding{InstallationID: pool.InstallationID, ClusterID: pool.ClusterID, IssuerEpoch: pool.IssuerEpoch, PodUID: custodyID(), ProcessEpoch: custodyID()}
	if _, err = reader.OwnerEndpoint(ctx, binding); err == nil {
		t.Fatal("reader worked without RBAC")
	}
	subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: "discovery", Namespace: ns.Name}}
	_, err = admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "owner-discovery"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "owner-discovery"}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "owner-discovery"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "discovery"}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"services", "serviceaccounts"}, ResourceNames: []string{"owner"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"owner"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: []string{"get"}},
		{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"list"}},
	}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "discovery"}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "discovery"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var found value.OwnerEndpoint
	var lastErr error
	for ctx.Err() == nil {
		pods, e := admin.CoreV1().Pods(ns.Name).List(ctx, meta.ListOptions{LabelSelector: "app=owner-discovery"})
		if e != nil {
			t.Fatal(e)
		}
		if len(pods.Items) == 1 {
			binding.PodUID = string(pods.Items[0].UID)
			found, lastErr = reader.OwnerEndpoint(ctx, binding)
			if lastErr == nil {
				break
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	if ctx.Err() != nil || !found.Valid(time.Now()) || found.Binding != binding || found.ReplicaSetUID == "" || len(found.Addresses) == 0 {
		t.Fatalf("controller discovery did not become ready: %v", lastErr)
	}
	t.Log("actual EndpointSlice, restricted Pod, ReplicaSet, Deployment, Service and account identities resolved with read-only role")
	service = qualifyInstalledOwnerEndpointPorts(t, ctx, admin, client, pool, binding, service)
	wrong := binding
	wrong.ProcessEpoch = "invalid"
	if _, err = reader.OwnerEndpoint(ctx, wrong); err == nil {
		t.Fatal("invalid process accepted")
	}
	wrong = binding
	wrong.IssuerEpoch = custodyID()
	if _, err = reader.OwnerEndpoint(ctx, wrong); err == nil {
		t.Fatal("foreign issuer accepted")
	}
	wrong = binding
	wrong.PodUID = custodyID()
	if _, err = reader.OwnerEndpoint(ctx, wrong); err == nil {
		t.Fatal("unknown Pod accepted")
	}
	// A process UUID is only an expected TLS identity, not an API attestation.
	wrong = binding
	wrong.ProcessEpoch = custodyID()
	if result, e := reader.OwnerEndpoint(ctx, wrong); e != nil || result.Binding != wrong {
		t.Fatal("discovery incorrectly attested a process", e)
	}
	readonly, err := kubernetes.NewForConfig(limited)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readonly.CoreV1().Secrets(ns.Name).List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(err) {
		t.Fatal("discovery role can read credentials")
	}
	if err = readonly.CoreV1().Pods(ns.Name).Delete(ctx, found.Pod, meta.DeleteOptions{}); !apierrors.IsForbidden(err) {
		t.Fatal("discovery role can mutate Pods")
	}
	service.Spec.PublishNotReadyAddresses = true
	service, err = admin.CoreV1().Services(ns.Name).Update(ctx, service, meta.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.OwnerEndpoint(ctx, binding); err == nil {
		t.Fatal("unqualified readiness accepted")
	}
	service.Spec.PublishNotReadyAddresses = false
	service, err = admin.CoreV1().Services(ns.Name).Update(ctx, service, meta.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Even a still-listed endpoint cannot substitute for the actual pinned Pod.
	exerciseOwnerConfiguration(t, ctx, f, admin, config, pool, binding, reader, func(accepted app.OwnerConfigurationReader, lab *ownerConfigLab) {
		exerciseOwnerWorkloadProtection(t, ctx, admin, config, pool, found.Pod, func(guard *kube.OwnerWorkloadProtection, observer *kube.PermissionClient) {
			exerciseOwnerEnrollment(t, ctx, f, admin, config, pool, accepted, lab, guard, observer, ownerListener)
		})
	})
	if err = admin.CoreV1().Pods(ns.Name).Delete(ctx, found.Pod, meta.DeleteOptions{}); err != nil {
		if !apierrors.IsNotFound(err) {
			t.Fatal(err)
		}
	}
	if _, err = reader.OwnerEndpoint(ctx, binding); err == nil {
		t.Fatal("deleted owner remained discoverable")
	}
	t.Log("missing rights, foreign identity, readiness override, Pod deletion and forbidden credential/mutation checks passed")
}
