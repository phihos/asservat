package kubernetes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	auth "k8s.io/api/authentication/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Concrete TLS/native readers over a synthetic API. The connector's source is
// its fixed identity document; no guard, probe or source ConfigMap is read.
type connectorLifecycleFixture struct {
	reader             *ConnectorLifecycleReader
	request            app.ConnectorLifecycleRequest
	start              time.Time
	clock              atomic.Int64
	calls, reviews     atomic.Int32
	revoke, recreated  atomic.Bool
	sourceOrGuardReads atomic.Int32
}

func newConnectorLifecycleFixture(t *testing.T) (*connectorLifecycleFixture, context.Context) {
	t.Helper()
	f := &connectorLifecycleFixture{start: time.Now().UTC()}
	f.clock.Store(f.start.UnixNano())
	now := func() time.Time { return time.Unix(0, f.clock.Load()).UTC() }
	v := ownerFixtureObjects()
	v.deploy.Spec.Replicas = ptr.To(int32(1))
	v.deploy.Spec.Template.Spec.ServiceAccountName = v.pool.ServiceAccount
	v.rs.Spec.Replicas = ptr.To(int32(1))
	v.rs.Spec.Selector = v.deploy.Spec.Selector.DeepCopy()
	v.rs.Spec.Template.Spec.ServiceAccountName = v.pool.ServiceAccount
	peer := value.PeerBinding{InstallationID: v.binding.InstallationID, ClusterID: v.pool.ClusterID, IssuerEpoch: v.binding.IssuerEpoch, PeerID: ownerID(20), Role: value.ConnectorPeer}
	process := value.ConnectorProcessIdentity{Binding: peer, PodUID: v.binding.PodUID, ProcessEpoch: v.binding.ProcessEpoch}
	payload, _ := json.Marshal(map[string]int64{"iat": f.start.Add(-time.Second).Unix(), "exp": f.start.Add(time.Minute).Unix()})
	token := []byte("e30." + base64.RawURLEncoding.EncodeToString(payload) + ".synthetic-signature")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		switch r.URL.Path {
		case "/api/v1/namespaces/owners":
			permissionReply(w, v.ns)
		case "/apis/apps/v1/namespaces/owners/deployments/hub":
			d := v.deploy.DeepCopy()
			if f.recreated.Load() {
				d.UID = types.UID(ownerID(99))
			}
			permissionReply(w, d)
		case "/api/v1/namespaces/owners/serviceaccounts/hub":
			permissionReply(w, v.sa)
		case "/api/v1/namespaces/owners/pods/" + v.pod.Name:
			permissionReply(w, v.pod)
		case "/apis/apps/v1/namespaces/owners/replicasets/" + v.rs.Name:
			permissionReply(w, v.rs)
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			f.reviews.Add(1)
			var q auth.TokenReview
			if json.NewDecoder(r.Body).Decode(&q) != nil || q.Spec.Token != string(token) || len(q.Spec.Audiences) != 1 || q.Spec.Audiences[0] != ConnectorEnrollmentAudience(peer.ClusterID) {
				t.Error("wrong native token review")
			}
			permissionReply(w, auth.TokenReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}, Status: auth.TokenReviewStatus{Authenticated: !f.revoke.Load(), Audiences: q.Spec.Audiences,
				User: auth.UserInfo{Username: "system:serviceaccount:owners:hub", UID: v.pool.AccountUID, Extra: map[string]auth.ExtraValue{"authentication.kubernetes.io/pod-name": {v.pod.Name}, "authentication.kubernetes.io/pod-uid": {process.PodUID}}}}})
		default:
			f.sourceOrGuardReads.Add(1)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: roots}, BearerToken: "connector"}, v.pool.ClusterID, cfg.NamespaceRef{Name: v.pool.Namespace, UID: v.pool.NamespaceUID}, now)
	if err != nil {
		t.Fatal(err)
	}
	backing, _ := json.Marshal(connectorTestBacking(f.start.Truncate(time.Microsecond), peer))
	offer := contracts.RegionalOffer{Format: contracts.RegionalOfferFormat, InstallationID: peer.InstallationID, PermissionRootID: ownerID(5), IssuerEpoch: peer.IssuerEpoch, ConnectorServerSuffix: "connectors.example.invalid", ConnectorIssuerRoots: [][]byte{ownerConfigurationTestRoot(t, f.start)},
		Roles: contracts.ConnectorIdentityRoles{Source: "connector_source", Journal: "connector_journal", Acknowledgement: "connector_ack", Cleanup: "connector_cleanup", Verifier: "connector_verifier", Finalizer: "connector_finalizer"}, ConnectorBacking: backing}
	doc, err := ConnectorIdentityDocument(offer, peer.ClusterID, peer.PeerID, contracts.ConnectorDeployment{Namespace: v.pool.Namespace, ServiceAccount: v.pool.ServiceAccount, Deployment: v.pool.Deployment, ServingSlots: 2, RetainedProcesses: 8})
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewConnectorIdentitySource(client, doc, offer.PermissionRootID, peer)
	if err != nil {
		t.Fatal(err)
	}
	workload := ConnectorWorkload{Namespace: v.pool.Namespace, NamespaceUID: v.pool.NamespaceUID, Account: v.pool.ServiceAccount, AccountUID: v.pool.AccountUID, Deployment: v.pool.Deployment, DeploymentUID: v.pool.DeploymentUID, Digest: ConnectorWorkloadDigest(v.pool.ClusterID, v.pool.Namespace, v.pool.Deployment)}
	if _, err = NewConnectorLifecycleReader(client, source, ConnectorWorkload{Namespace: v.pool.Namespace, NamespaceUID: v.pool.NamespaceUID, Account: v.pool.ServiceAccount, Deployment: "other", Digest: workload.Digest}, connectorTokenFunc(nil)); err == nil {
		t.Fatal("workload of another Deployment accepted")
	}
	f.reader, err = NewConnectorLifecycleReader(client, source, workload, connectorTokenFunc(func(context.Context) ([]byte, error) { return bytes.Clone(token), nil }))
	if err != nil {
		t.Fatal(err)
	}
	csr := func() []byte {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		out, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	f.request = app.ConnectorLifecycleRequest{Binding: value.ConnectorLifecycleBinding{ID: ownerID(80), Purpose: value.ConnectorLifecycleEnroll, Process: process, RequestedAt: f.start, NotAfter: f.start.Add(5 * time.Second)}, Request: value.ConnectorProcessRequest{Process: process, ClientCSRDER: csr(), ServerCSRDER: csr()}}
	ctx, cancel := context.WithDeadline(context.Background(), f.request.Binding.NotAfter)
	t.Cleanup(cancel)
	return f, ctx
}

func TestConnectorLifecycleNativeOwnsOriginalAndIndependentFinal(t *testing.T) {
	f, ctx := newConnectorLifecycleFixture(t)
	client, _ := mtls.EnrollmentKey(f.request.Request.ClientCSRDER)
	op, err := f.reader.BeginConnectorLifecycle(ctx, f.request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	f.request.Request.ClientCSRDER[0] ^= 1
	first, err := op.Read(ctx, value.ConnectorLifecycleInitial)
	if err != nil || first.Original.ClientKeyDigest != client || first.Original.ProtectionDigest != f.reader.workload.Digest {
		t.Fatal("initial native bracket", err)
	}
	prior := first
	for _, phase := range []value.ConnectorLifecyclePhase{value.ConnectorLifecycleBeforeEffect, value.ConnectorLifecycleBeforeActivation, value.ConnectorLifecycleFinal} {
		f.clock.Store(f.start.Add(time.Duration(phase) * time.Millisecond).UnixNano())
		next, err := op.Read(ctx, phase)
		if err != nil || !next.Continues(prior) || !next.Original.ObservedAt.Equal(first.Original.ObservedAt) || !next.Original.FreshUntil.Equal(first.Original.FreshUntil) {
			t.Fatal("native or value dates relabeled", phase, err)
		}
		if phase == value.ConnectorLifecycleFinal && next.FinalProof == nil {
			t.Fatal("final proof lacks actual later observation")
		}
		prior = next
	}
	if f.sourceOrGuardReads.Load() != 0 {
		t.Fatal("lifecycle read a source ConfigMap or guard", f.sourceOrGuardReads.Load())
	}
}

func TestConnectorLifecycleNativeRefusesRevokedTokenAndRecreatedDeployment(t *testing.T) {
	for name, change := range map[string]func(*connectorLifecycleFixture){
		"revoked":   func(f *connectorLifecycleFixture) { f.revoke.Store(true) },
		"recreated": func(f *connectorLifecycleFixture) { f.recreated.Store(true) },
	} {
		t.Run(name, func(t *testing.T) {
			f, ctx := newConnectorLifecycleFixture(t)
			op, err := f.reader.BeginConnectorLifecycle(ctx, f.request)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(op.Close)
			if _, err = op.Read(ctx, value.ConnectorLifecycleInitial); err != nil {
				t.Fatal(err)
			}
			change(f)
			if _, err = op.Read(ctx, value.ConnectorLifecycleBeforeActivation); err == nil {
				t.Fatal("changed native fact accepted")
			}
		})
	}
}
