package kms

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/google/uuid"
	auth "k8s.io/api/authentication/v1"
	access "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

type ownerProviderNativeFixture struct {
	t                                              *testing.T
	ctx                                            context.Context
	api                                            *kubernetes.Clientset
	http                                           *http.Client
	adminEndpoint, apiEndpoint, apiCA, reviewerJWT string
	input                                          contracts.OwnerDeployment
	recipe                                         OwnerProviderRecipe
	namespace                                      string
	owner, reviewer                                *core.ServiceAccount
	pod, reviewerPod                               *core.Pod
	jwt                                            []byte
	controls                                       [4]*ownerProviderControl
	credentials                                    [4]*ownerProviderCredential
}

func newOwnerProviderNativeFixture(t *testing.T) *ownerProviderNativeFixture {
	t.Helper()
	if os.Getenv("ASSERVAT_OWNER_PROVIDER_AUTH_NATIVE") != "1" {
		t.Skip("requires the closed owned context provider-auth mode")
	}
	var input struct {
		KMS             string
		NativeProviders struct {
			KMS, S3, Postgres string
			Root              []byte
		}
		Clusters []struct{ Config string }
	}
	raw, err := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if err != nil || json.Unmarshal(raw, &input) != nil || len(input.Clusters) != 1 || input.NativeProviders.KMS == "" {
		t.Fatal("owned one-cluster provider fixture unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	t.Cleanup(cancel)
	config, err := clientcmd.BuildConfigFromFlags("", input.Clusters[0].Config)
	if err != nil {
		t.Fatal("owned Kubernetes configuration", err)
	}
	config.Timeout = 5 * time.Second
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	ca := config.CAData
	if len(ca) == 0 {
		ca, err = os.ReadFile(config.CAFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	block, _ := pem.Decode(ca)
	if block == nil {
		t.Fatal("owned Kubernetes CA")
	}
	roots := x509.NewCertPool()
	certificate, err := x509.ParseCertificate(input.NativeProviders.Root)
	if err != nil {
		t.Fatal("owned provider TLS root", err)
	}
	roots.AddCert(certificate)
	h := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(h.CloseIdleConnections)
	namespace := "owner-auth-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ns, err := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: namespace, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("provider namespace", err)
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		if e := api.CoreV1().Namespaces().Delete(c, namespace, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: ptr.To(ns.UID)}}); e != nil {
			t.Errorf("provider namespace cleanup: %v", e)
		}
	})
	f := &ownerProviderNativeFixture{t: t, ctx: ctx, api: api, http: h, adminEndpoint: input.NativeProviders.KMS, namespace: namespace, apiCA: string(ca)}
	for name, dest := range map[string]**core.ServiceAccount{"owner": &f.owner, "reviewer": &f.reviewer} {
		*dest, err = api.CoreV1().ServiceAccounts(namespace).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
		if err != nil {
			t.Fatal("provider service account", err)
		}
	}
	roleName := namespace + "-reviewer"
	role, err := api.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: roleName}, Rules: []rbac.PolicyRule{{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		if e := api.RbacV1().ClusterRoles().Delete(c, roleName, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: ptr.To(role.UID)}}); e != nil {
			t.Errorf("reviewer role cleanup: %v", e)
		}
	})
	binding, err := api.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: roleName}, RoleRef: rbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: roleName}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: f.reviewer.Name, Namespace: namespace}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		if e := api.RbacV1().ClusterRoleBindings().Delete(c, roleName, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: ptr.To(binding.UID)}}); e != nil {
			t.Errorf("reviewer binding cleanup: %v", e)
		}
	})
	check, err := api.AuthorizationV1().SubjectAccessReviews().Create(ctx, &access.SubjectAccessReview{Spec: access.SubjectAccessReviewSpec{User: "system:serviceaccount:" + namespace + ":" + f.owner.Name, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + namespace, "system:authenticated"}, ResourceAttributes: &access.ResourceAttributes{Group: "authentication.k8s.io", Resource: "tokenreviews", Verb: "create"}}}, meta.CreateOptions{})
	if err != nil || check.Status.Allowed {
		t.Fatal("owner unexpectedly has TokenReview privilege", err)
	}
	nodes, err := api.CoreV1().Nodes().List(ctx, meta.ListOptions{Limit: 2})
	if err != nil || len(nodes.Items) != 1 || nodes.Continue != "" {
		t.Fatal("exact owned single control-plane node unavailable", err)
	}
	// The harness joins this exact owned node to the provider network. Its
	// native name is also an API serving certificate SAN; no TLS override.
	f.apiEndpoint = "https://" + nodes.Items[0].Name + ":6443"
	f.reviewerPod = f.createPod("reviewer", f.reviewer.Name)
	f.reviewerJWT = string(f.token(f.reviewer, f.reviewerPod, nil))
	f.pod = f.createPod("original", f.owner.Name)
	installation, cluster := uuid.NewString(), uuid.NewString()
	f.jwt = f.token(f.owner, f.pod, []string{contracts.OwnerProviderAudience(installation, cluster)})
	secret, err := api.CoreV1().Secrets(namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "audit-credentials"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"audit-storage.json": []byte(`{"synthetic":true}`)}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(input.NativeProviders.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	f.input = contracts.OwnerDeployment{Format: contracts.OwnerDeploymentFormat, InstallationID: installation, ClusterID: cluster, Namespace: contracts.WorkerObjectReference{Name: namespace, UID: string(ns.UID)}, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: f.apiEndpoint, Roots: [][]byte{block.Bytes}}, Postgres: contracts.OwnerPostgresEndpoint{Host: host, Port: port, Database: "custody_test", Roots: [][]byte{input.NativeProviders.Root}, MaxConnections: 1}, AuditStore: contracts.OwnerAuditStore{Endpoint: input.NativeProviders.S3, Roots: [][]byte{input.NativeProviders.Root}, Region: "us-east-1", Bucket: "owner-auth"}, KeyService: contracts.OwnerKeyService{Endpoint: input.NativeProviders.KMS, Roots: [][]byte{input.NativeProviders.Root}, AuditMount: "owner-auth-transit", AuditKey: "audit", PKIMount: "owner-auth-pki", ServerRole: "server", ClientRole: "client"}}
	f.admin(http.MethodPost, "sys/auth/owner-auth", map[string]any{"type": "kubernetes"}, 204)
	mounts := f.admin(http.MethodGet, "sys/auth", nil, 200)
	data, ok := mounts["data"].(map[string]any)
	if !ok {
		t.Fatal("auth mount data")
	}
	mount, ok := data["owner-auth/"].(map[string]any)
	if !ok {
		t.Fatal("exact auth mount")
	}
	accessor, ok := mount["accessor"].(string)
	if !ok || mount["type"] != "kubernetes" {
		t.Fatal("exact auth mount identity")
	}
	f.recipe, err = OwnerProviderRecipeFor(f.input, "owner-auth", accessor, contracts.WorkerObjectReference{Name: f.owner.Name, UID: string(f.owner.UID)}, contracts.WorkerObjectReference{Name: secret.Name, UID: string(secret.UID)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.configureReviewer(f.reviewerJWT)
	for _, entry := range f.recipe.Roles {
		f.admin(http.MethodPost, "sys/policies/acl/"+entry.Name, map[string]string{"policy": string(entry.Policy)}, 204)
		f.admin(http.MethodPost, "auth/owner-auth/role/"+entry.Name, json.RawMessage(entry.Role), 204)
	}
	for i, entry := range f.recipe.Roles {
		f.controls[i], err = newOwnerProviderControl(f.input, f.recipe.Profile, entry.Purpose, h, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(f.controls[i].close)
	}
	t.Cleanup(func() {
		for i, c := range f.credentials {
			if c != nil {
				call, end := context.WithTimeout(context.Background(), 5*time.Second)
				_ = f.controls[i].revoke(call, c)
				end()
				c.destroy()
			}
		}
		clear(f.jwt)
	})
	return f
}

func (f *ownerProviderNativeFixture) admin(method, path string, body any, want int) map[string]any {
	f.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	defer clear(raw)
	call, end := context.WithTimeout(f.ctx, 5*time.Second)
	defer end()
	r, err := http.NewRequestWithContext(call, method, f.adminEndpoint+"/v1/"+path, bytes.NewReader(raw))
	if err != nil {
		f.t.Fatal(err)
	}
	r.GetBody = nil
	r.Header.Set("X-Vault-Token", "synthetic-root")
	r.Header.Set("Content-Type", "application/json")
	response, err := f.http.Do(r)
	if err != nil {
		f.t.Fatal("owned provider admin request unavailable", path)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		f.t.Fatalf("owned provider admin %s status %d, want %d", path, response.StatusCode, want)
	}
	if want == 204 {
		return nil
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	defer clear(encoded)
	var out map[string]any
	if err != nil || len(encoded) > 65536 || json.Unmarshal(encoded, &out) != nil {
		f.t.Fatal("owned provider admin reply invalid", path)
	}
	return out
}

func (f *ownerProviderNativeFixture) createPod(name, account string) *core.Pod {
	f.t.Helper()
	pod, err := f.api.CoreV1().Pods(f.namespace).Create(f.ctx, &core.Pod{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: core.PodSpec{ServiceAccountName: account, AutomountServiceAccountToken: ptr.To(false), SchedulingGates: []core.PodSchedulingGate{{Name: "asservat.io/provider-auth-test"}}, SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Containers: []core.Container{{Name: "inert", Image: "registry.invalid/never-run@sha256:" + strings.Repeat("a", 64), SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}}, meta.CreateOptions{})
	if err != nil {
		f.t.Fatal("inert provider-bound Pod", err)
	}
	return pod
}

func (f *ownerProviderNativeFixture) token(account *core.ServiceAccount, pod *core.Pod, audiences []string) []byte {
	f.t.Helper()
	reply, err := f.api.CoreV1().ServiceAccounts(f.namespace).CreateToken(f.ctx, account.Name, &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: audiences, ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID}}}, meta.CreateOptions{})
	if err != nil || reply.Status.Token == "" {
		f.t.Fatal("real bound token request", err)
	}
	return []byte(reply.Status.Token)
}

func (f *ownerProviderNativeFixture) configureReviewer(jwt string) {
	f.admin(http.MethodPost, "auth/owner-auth/config", map[string]any{"kubernetes_host": f.apiEndpoint, "kubernetes_ca_cert": f.apiCA, "token_reviewer_jwt": jwt, "disable_local_ca_jwt": true, "disable_iss_validation": true}, 204)
}

func (f *ownerProviderNativeFixture) deletePod(pod *core.Pod) {
	f.t.Helper()
	if err := f.api.CoreV1().Pods(f.namespace).Delete(f.ctx, pod.Name, meta.DeleteOptions{GracePeriodSeconds: ptr.To(int64(0)), Preconditions: &meta.Preconditions{UID: ptr.To(types.UID(pod.UID))}}); err != nil {
		f.t.Fatal("delete original gated provider Pod", err)
	}
}

// Helpers report failures on the executing subtest rather than aborting its
// parent. This fixture is deliberately sequential; credentials and provider
// roles are retained between the separately named protocol observations.
func (f *ownerProviderNativeFixture) run(parent *testing.T, name string, body func(*testing.T)) bool {
	return parent.Run(name, func(t *testing.T) {
		old := f.t
		f.t = t
		defer func() { f.t = old }()
		body(t)
	})
}
