package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type ownerEnrollmentTokenFunc func(context.Context) ([]byte, error)

func (f ownerEnrollmentTokenFunc) ReadOwnerPodToken(ctx context.Context) ([]byte, error) {
	return f(ctx)
}

// This composes actual native admission, audited SQL configuration, online
// TokenReview and controller-created Pods. Initial recovery/issuer bootstrap remains
// fixture-supplied; current proof is composed with real signing and activation.
func exerciseOwnerEnrollment(t *testing.T, ctx context.Context, f fixture, admin kubernetes.Interface, kubeConfig *rest.Config, pool value.OwnerPool, accepted app.OwnerConfigurationReader, lab *ownerConfigLab, guard *kube.OwnerWorkloadProtection, observer *kube.PermissionClient, ownerListener net.Listener) {
	t.Helper()
	accepted = nativeOwnerConfiguration{accepted, lab, pool.InstallationID}
	_, err := admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "owner-enrollment-token-review"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: "owner-workload-reader", Namespace: pool.Namespace}}
	_, err = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "owner-enrollment-token-review"}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "owner-enrollment-token-review"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.RbacV1().Roles(pool.Namespace).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "owner-enrollment-reader"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}, {APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{pool.ServiceAccount}, Verbs: []string{"get"}}, {APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.RbacV1().RoleBindings(pool.Namespace).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "owner-enrollment-reader"}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "owner-enrollment-reader"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// A readiness gate keeps the real new Deployment revision unready until its
	// first certificate could have been obtained. No endpoint override or fake
	// status snapshot is used to make this bootstrap path pass.
	deployment, err := admin.AppsV1().Deployments(pool.Namespace).Get(ctx, pool.Deployment, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	gate := core.PodConditionType("asservat.io/OwnerCertificateReady")
	deployment.Spec.Template.Spec.ReadinessGates = []core.PodReadinessGate{{ConditionType: gate}}
	_, err = admin.AppsV1().Deployments(pool.Namespace).Update(ctx, deployment, meta.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var pod core.Pod
	until := time.Now().Add(20 * time.Second)
	for time.Now().Before(until) {
		pods, e := admin.CoreV1().Pods(pool.Namespace).List(ctx, meta.ListOptions{LabelSelector: "app=owner-discovery"})
		if e != nil {
			t.Fatal(e)
		}
		for _, candidate := range pods.Items {
			if candidate.DeletionTimestamp == nil && candidate.Spec.NodeName != "" && len(candidate.Spec.ReadinessGates) == 1 && candidate.Spec.ReadinessGates[0].ConditionType == gate && (candidate.Status.Phase == core.PodPending || candidate.Status.Phase == core.PodRunning) {
				pod = candidate
			}
		}
		if pod.Name != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if pod.Name == "" {
		t.Fatal("controller did not create a scheduled readiness-gated owner")
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == core.PodReady && condition.Status == core.ConditionTrue {
			t.Fatal("bootstrap test unexpectedly used a Ready Pod")
		}
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	b := value.OwnerBinding{InstallationID: pool.InstallationID, ClusterID: pool.ClusterID, IssuerEpoch: pool.IssuerEpoch, PodUID: string(pod.UID), ProcessEpoch: custodyID()}
	request := value.OwnerEnrollmentRequest{Binding: b, Usage: "server", CSRDER: csr}
	mint := func(audience string, bound bool) []byte {
		t.Helper()
		spec := auth.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: ptr.To(int64(600))}
		if bound {
			spec.BoundObjectRef = &auth.BoundObjectReference{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID}
		}
		token, e := admin.CoreV1().ServiceAccounts(pool.Namespace).CreateToken(ctx, pool.ServiceAccount, &auth.TokenRequest{Spec: spec}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		return []byte(token.Status.Token)
	}
	token := mint(kube.OwnerEnrollmentAudience(pool.InstallationID), true)
	defer clear(token)
	var supplied []byte
	tokens := ownerEnrollmentTokenFunc(func(context.Context) ([]byte, error) { supplied = bytes.Clone(token); return supplied, nil })
	attester, err := kube.NewOwnerEnrollmentAttester(observer, accepted, guard, tokens)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := attester.ReadOwnerEnrollmentProof(ctx, request)
	if err != nil || !proof.Valid(time.Now()) || proof.Binding != b || proof.Pod != pod.Name || proof.ReplicaSetUID == "" {
		t.Fatal("pre-Ready enrollment proof", err)
	}
	if !bytes.Equal(supplied, make([]byte, len(supplied))) {
		t.Fatal("token buffer retained")
	}
	endpoints, err := kube.NewOwnerEndpoints(observer, pool)
	if err != nil {
		t.Fatal(err)
	}
	// Give discovery its existing separate read surface, so its failure is
	// actual readiness rejection rather than missing EndpointSlice/Service RBAC.
	_, err = admin.RbacV1().Roles(pool.Namespace).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "owner-enrollment-discovery"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"services"}, ResourceNames: []string{pool.Service}, Verbs: []string{"get"}}, {APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"list"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.RbacV1().RoleBindings(pool.Namespace).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "owner-enrollment-discovery"}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "owner-enrollment-discovery"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = endpoints.OwnerEndpoint(ctx, b); err == nil {
		t.Fatal("unready owner became routable")
	}
	for _, mode := range []string{"client-purpose", "wrong-audience", "unbound", "wrong-pod", "wrong-issuer", "invalid-csr"} {
		candidate := request
		current := token
		switch mode {
		case "client-purpose":
			candidate.Usage = "client"
		case "wrong-audience":
			current = mint(kube.DownloadPeerAudience(pool.InstallationID), true)
		case "unbound":
			current = mint(kube.OwnerEnrollmentAudience(pool.InstallationID), false)
		case "wrong-pod":
			candidate.Binding.PodUID = custodyID()
		case "wrong-issuer":
			candidate.Binding.IssuerEpoch = custodyID()
		case "invalid-csr":
			candidate.CSRDER = bytes.Repeat([]byte{1}, 64)
		}
		s, e := kube.NewOwnerEnrollmentAttester(observer, accepted, guard, ownerEnrollmentTokenFunc(func(context.Context) ([]byte, error) { return bytes.Clone(current), nil }))
		if e != nil {
			t.Fatal(e)
		}
		result, e := s.ReadOwnerEnrollmentProof(ctx, candidate)
		if mode == "client-purpose" {
			if e != nil || !result.Valid(time.Now()) || result.Usage != "client" {
				t.Fatal("client proof", e)
			}
		} else if e == nil {
			t.Fatal("invalid proof accepted", mode)
		}
		if mode == "wrong-audience" || mode == "unbound" {
			clear(current)
		}
	}
	exerciseNativeOwnerDeployment(t, ctx, f, admin, kubeConfig, pool, accepted, pod, token, ownerListener)
	native := exerciseNativeOwnerActivation(t, ctx, f, admin, pool, accepted, lab, guard, endpoints, attester, request, key)
	native("before-ready")
	// Mark only the test readiness gate satisfied. Normal kubelet/controller
	// status must still make this exact Pod routable; it was already attestable.
	p, err := admin.CoreV1().Pods(pool.Namespace).Get(ctx, pod.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p.Status.Conditions = append(p.Status.Conditions, core.PodCondition{Type: gate, Status: core.ConditionTrue, LastTransitionTime: meta.Now(), Reason: "AuditedCertificatesActivated"})
	if _, err = admin.CoreV1().Pods(pool.Namespace).UpdateStatus(ctx, p, meta.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	until = time.Now().Add(20 * time.Second)
	for time.Now().Before(until) {
		if _, err = endpoints.OwnerEndpoint(ctx, b); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("same owner did not become routable after readiness", err)
	}
	if _, err = attester.ReadOwnerEnrollmentProof(ctx, request); err != nil {
		t.Fatal("post-readiness proof", err)
	}
	native("ready")
	if err = admin.CoreV1().Pods(pool.Namespace).Delete(ctx, pod.Name, meta.DeleteOptions{GracePeriodSeconds: ptr.To(int64(0))}); err != nil {
		t.Fatal(err)
	}
	if _, err = attester.ReadOwnerEnrollmentProof(ctx, request); err == nil {
		t.Fatal("deleted Pod token retained enrollment authority")
	}
	native("deleted")
	t.Log("real Pod-bound token/CSR + audited configuration + native workload guard proved enrollment before readiness; routing waited, then succeeded; foreign/unbound/deleted tokens denied")
}
