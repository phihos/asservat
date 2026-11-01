package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	auth "k8s.io/api/authentication/v1"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type actualDownloadToken struct {
	mu    sync.Mutex
	token []byte
}

func (s *actualDownloadToken) ReadDownloadPeerToken(context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.token), nil
}
func (s *actualDownloadToken) set(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.token)
	s.token = bytes.Clone(b)
}

func TestDownloadWorkerProofWithRealKubernetesTLS(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run make context-integration for owned Kubernetes")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var f fixture
	if json.Unmarshal(raw, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("missing fixtures")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	config, e := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if e != nil {
		t.Fatal(e)
	}
	admin, e := kubernetes.NewForConfig(config)
	if e != nil {
		t.Fatal(e)
	}
	sample, e := admin.CoreV1().Pods(f.Clusters[0].Pod.Namespace).Get(ctx, f.Clusters[0].Pod.Name, meta.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	ns, e := admin.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "download-worker-proof", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	account, e := admin.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "acquisition"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	no := false
	nonroot := true
	uid := int64(65532)
	podSpec := core.PodSpec{ServiceAccountName: account.Name, AutomountServiceAccountToken: &no, RestartPolicy: core.RestartPolicyNever, SecurityContext: &core.PodSecurityContext{RunAsNonRoot: &nonroot, RunAsUser: &uid, SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Containers: []core.Container{{Name: "fixture", Image: sample.Spec.Containers[0].Image, ImagePullPolicy: core.PullIfNotPresent, SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: &no, Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}
	job, e := admin.BatchV1().Jobs(ns.Name).Create(ctx, &batch.Job{ObjectMeta: meta.ObjectMeta{Name: "download"}, Spec: batch.JobSpec{Template: core.PodTemplateSpec{Spec: podSpec}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	var pod *core.Pod
	limit := time.Now().Add(20 * time.Second)
	for time.Now().Before(limit) {
		list, e := admin.CoreV1().Pods(ns.Name).List(ctx, meta.ListOptions{LabelSelector: "batch.kubernetes.io/job-name=" + job.Name})
		if e != nil {
			t.Fatal(e)
		}
		if len(list.Items) == 1 && list.Items[0].Status.Phase == core.PodRunning {
			pod = &list.Items[0]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if pod == nil {
		t.Fatal("owned synthetic Job pod did not become ready")
	}
	job, e = admin.BatchV1().Jobs(ns.Name).Get(ctx, job.Name, meta.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	b := value.KeyWorkerBinding{InstallationID: custodyID(), DownloadID: custodyID(), ClusterID: custodyID(), Namespace: ns.Name, NamespaceUID: string(ns.UID), ServiceAccount: account.Name, ServiceAccountUID: string(account.UID), Job: job.Name, JobUID: string(job.UID), Pod: pod.Name, PodUID: string(pod.UID)}
	pj, _ := json.Marshal(pod.Spec)
	jj, _ := json.Marshal(job.Spec)
	b.PodSpec, e = kube.WorkerSpecDigest("Pod", pj)
	if e != nil {
		t.Fatal(e)
	}
	b.JobSpec, e = kube.WorkerSpecDigest("Job", jj)
	if e != nil {
		t.Fatal(e)
	}
	var returnedExpiry time.Time
	token := func(audience string, bound *core.Pod) []byte {
		t.Helper()
		life := int64(600)
		req := &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: &life}}
		if bound != nil {
			req.Spec.BoundObjectRef = &auth.BoundObjectReference{APIVersion: "v1", Kind: "Pod", Name: bound.Name, UID: bound.UID}
		}
		v, e := admin.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, account.Name, req, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		returnedExpiry = v.Status.ExpirationTimestamp.Time
		return []byte(v.Status.Token)
	}
	original := token(kube.DownloadPeerAudience(b.InstallationID), pod)
	originalExpiry := returnedExpiry
	defer clear(original)
	tokens := &actualDownloadToken{}
	tokens.set(original)
	defer tokens.set(nil)
	_, e = admin.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "reviewer"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	reviewToken, e := admin.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, "reviewer", &auth.TokenRequest{}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	limited := &rest.Config{Host: config.Host, BearerToken: reviewToken.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: config.CAData, CAFile: config.CAFile}}
	counts := &nativeProofAPICounts{}
	limited.WrapTransport = counts.wrap
	client, e := kube.NewPermissionClient(limited, b.ClusterID, cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	source, e := kube.NewDownloadPeerAttester(client, b, tokens)
	if e != nil {
		t.Fatal(e)
	}
	var peerVerifier *mtls.KeyPeerVerifier
	tlsFixture := newKeyTLSFor(t, b.InstallationID, "artifact", nil, nil, func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, e := peerVerifier.Verify(r.TLS)
			if e != nil {
				w.WriteHeader(403)
				return
			}
			proof, e := source.ReadNativeResponsePeerProof(r.Context(), b.DownloadID, p)
			if e != nil {
				w.WriteHeader(403)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(proof)
		})
	})
	peerVerifier, e = mtls.NewKeyPeerVerifier(tlsFixture.roots, b.InstallationID, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	cert := tlsFixture.certificateForPeer(t, "acquisition", b.PodUID)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: tlsFixture.roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	invoke := func(want int) evidence.NativeResponsePeerProof {
		t.Helper()
		response, e := httpClient.Get(tlsFixture.server.URL)
		if e != nil {
			t.Fatal("private TLS request failed", e)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("private attestation status=%d want=%d", response.StatusCode, want)
		}
		var p evidence.NativeResponsePeerProof
		if want == 200 {
			if json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&p) != nil || !p.Valid(time.Now()) || p.Proof.Binding != b || !p.TokenNotAfter.Equal(originalExpiry) {
				t.Fatal("incomplete live proof")
			}
		}
		return p
	}
	invoke(403)
	subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: "reviewer", Namespace: ns.Name}}
	_, e = admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "download-worker-proof"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}}, {APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	_, e = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "download-worker-proof"}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "download-worker-proof"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	_, e = admin.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "worker-proof"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{pod.Name}, Verbs: []string{"get"}}, {APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{account.Name}, Verbs: []string{"get"}}, {APIGroups: []string{"batch"}, Resources: []string{"jobs"}, ResourceNames: []string{job.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	_, e = admin.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "worker-proof"}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "worker-proof"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	tokens.set(nil)
	beforeMissing := counts.snapshot()
	invoke(403)
	if missing := counts.snapshot().subtract(beforeMissing); missing != (nativeProofAPISnapshot{}) {
		t.Fatal("missing token caused Kubernetes requests", missing)
	}
	tokens.set(original)
	beforeInitial := counts.snapshot()
	proof := invoke(200).Proof
	initialCost := counts.snapshot().subtract(beforeInitial)
	if initialCost != (nativeProofAPISnapshot{Reviews: 2, Gets: 8}) {
		t.Fatal("initial real attestation API cost changed", initialCost)
	}
	qualifyNativeResponseRealProof(t, ctx, limited, client, source, tokens, b, proof.Peer, originalExpiry, counts)
	if proof.TokenDigest == (artifact.Digest{}) || proof.FreshUntil.Sub(proof.ObservedAt) > 5*time.Second {
		t.Fatal("unbounded token proof")
	}
	restricted, e := kubernetes.NewForConfig(limited)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restricted.CoreV1().Pods(ns.Name).List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("reviewer can list pods")
	}
	if _, e = restricted.CoreV1().Secrets(ns.Name).List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("reviewer can read credentials")
	}
	if _, e = restricted.CoreV1().Pods(ns.Name).Patch(ctx, pod.Name, types.MergePatchType, []byte(`{"metadata":{"labels":{"forged":"true"}}}`), meta.PatchOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("reviewer can change worker")
	}
	workerConfig := rest.CopyConfig(limited)
	workerConfig.BearerToken = string(original)
	worker, e := kubernetes.NewForConfig(workerConfig)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = worker.AuthenticationV1().TokenReviews().Create(ctx, &auth.TokenReview{Spec: auth.TokenReviewSpec{Token: string(original)}}, meta.CreateOptions{}); e == nil {
		t.Fatal("worker token gained review authority")
	}
	for _, bound := range []*core.Pod{nil, pod} {
		aud := kube.DownloadPeerAudience(b.InstallationID)
		if bound != nil {
			aud = "https://wrong-audience.invalid"
		}
		wrong := token(aud, bound)
		tokens.set(wrong)
		clear(wrong)
		invoke(403)
	}
	tokens.set(original)
	invoke(200)
	// A second real pod with the same account and owner cannot substitute for
	// the independently pinned worker, even with a valid dedicated-audience token.
	other, e := admin.CoreV1().Pods(ns.Name).Create(ctx, &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "other", OwnerReferences: pod.OwnerReferences}, Spec: podSpec}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	wrong := token(kube.DownloadPeerAudience(b.InstallationID), other)
	tokens.set(wrong)
	clear(wrong)
	invoke(403)
	tokens.set(original)
	if _, e = admin.CoreV1().Pods(ns.Name).Patch(ctx, pod.Name, types.MergePatchType, []byte(`{"spec":{"activeDeadlineSeconds":600}}`), meta.PatchOptions{}); e != nil {
		t.Fatal(e)
	}
	invoke(403) // same pod UID, changed execution specification
	pod, e = admin.CoreV1().Pods(ns.Name).Get(ctx, pod.Name, meta.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	updated := b
	pj, _ = json.Marshal(pod.Spec)
	updated.PodSpec, e = kube.WorkerSpecDigest("Pod", pj)
	if e != nil {
		t.Fatal(e)
	}
	// Directly exercise the deleting-object guard with a fresh fixture dispatch
	// pin, so a spec mismatch cannot be the reason this deletion case passes.
	deleting, e := kube.NewDownloadPeerAttester(client, updated, tokens)
	if e != nil {
		t.Fatal(e)
	}
	currentPeer := proof.Peer
	if _, e = deleting.ReadDownloadPeerProof(ctx, b.DownloadID, currentPeer); e != nil {
		t.Fatal("updated synthetic dispatch pin", e)
	}
	if _, e = admin.CoreV1().Pods(ns.Name).Patch(ctx, pod.Name, types.MergePatchType, []byte(`{"metadata":{"finalizers":["asservat.io/synthetic-proof"]}}`), meta.PatchOptions{}); e != nil {
		t.Fatal(e)
	}
	zero := int64(0)
	if e = admin.CoreV1().Pods(ns.Name).Delete(ctx, pod.Name, meta.DeleteOptions{GracePeriodSeconds: &zero}); e != nil {
		t.Fatal(e)
	}
	if _, e = deleting.ReadDownloadPeerProof(ctx, b.DownloadID, currentPeer); e == nil {
		t.Fatal("deleting pod retained peer identity")
	}
	if _, e = admin.CoreV1().Pods(ns.Name).Patch(ctx, pod.Name, types.MergePatchType, []byte(`{"metadata":{"finalizers":[]}}`), meta.PatchOptions{}); e != nil {
		t.Fatal(e)
	}
	t.Log("real response producer/TokenRequest expiry, two TokenReviews/eight GETs, zero repeated-response Kubernetes calls, dedicated-audience TokenReview, pod binding, live Job/account/spec checks, verified mTLS identity, API role separation and deleting-pod rejection passed; dispatch and certificate issuance remain fixtures")
}
