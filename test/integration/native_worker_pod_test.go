package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/native"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// This fixture has no dispatchable native operation. It qualifies the compiled
// worker's real mTLS/Pod-token idle path, not SQL command admission or transfer.
type nativePodIdleAdmission struct {
	bootstrap          *ownedWorkerBootstrap
	client             *kube.PermissionClient
	verifier           *mtls.KeyPeerVerifier
	mu                 sync.Mutex
	lastNonce          string
	lastAt             time.Time
	accepted, rejected atomic.Int64
}

func (a *nativePodIdleAdmission) OpenNative(ctx context.Context, state *tls.ConnectionState, h contracts.NativeHello) (native.Conversation, error) {
	started := time.Now().UTC()
	fail := func() (native.Conversation, error) { a.rejected.Add(1); return nil, artifact.ErrDownloadUnavailable }
	peer, err := a.verifier.Verify(state)
	if err != nil || state.NegotiatedProtocol != "h2" || !contracts.ValidWorkerNonce(h.Nonce) {
		return fail()
	}
	a.bootstrap.exchange.mu.Lock()
	worker, configuration, issued := a.bootstrap.exchange.worker, a.bootstrap.exchange.configuration, a.bootstrap.exchange.issued
	a.bootstrap.exchange.mu.Unlock()
	if configuration == nil || peer != issued.Peer || h.Reference.InstallationID != worker.Binding.InstallationID || h.Reference.SessionID != worker.Intent.SessionID || h.Reference.WorkerID != worker.Intent.ID || h.Reference.OperationID != "" || h.Reference.Fence != 0 {
		return fail()
	}
	current, err := (fixtureWorkerIdentity{worker, configuration}).ReadDownloadWorkerIdentity(ctx, worker.Intent.SessionID, peer)
	if err != nil {
		return fail()
	}
	attester, err := kube.NewDispatchedDownloadPeerAttester(a.client, fixtureWorkerIdentity{worker, configuration}, receivedWorkerToken(h.WorkerToken))
	if err != nil {
		return fail()
	}
	proof, err := attester.ReadDownloadPeerProof(ctx, worker.Intent.SessionID, peer)
	if err != nil {
		return fail()
	}
	idle := &evidence.NativeIdle{Worker: current.Acquisition(), Proof: proof.Acquisition(), ObservedAt: started, Until: identity.Earlier(started.Add(5*time.Second), identity.Earlier(current.FreshUntil, proof.FreshUntil))}
	if !idle.Valid(time.Now()) || ctx.Err() != nil {
		return fail()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Actual second HTTP conversation must use a different nonce and preserve
	// the required backoff, rather than replaying an uncertain request.
	if h.Nonce == a.lastNonce || !a.lastAt.IsZero() && started.Before(a.lastAt.Add(contracts.NativeIdleRetry)) {
		return fail()
	}
	a.lastNonce, a.lastAt = h.Nonce, started
	a.accepted.Add(1)
	return nil, idle
}

func configureNativePodFixture(t *testing.T, ctx context.Context, admin kubernetes.Interface, namespace, image string, bootstrap *ownedWorkerBootstrap, client *kube.PermissionClient, p *value.DownloadWorkerProfile, wire *contracts.WorkerControl) *nativePodIdleAdmission {
	t.Helper()
	root, err := x509.ParseCertificate(bootstrap.issuerRoot)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	verifier, err := mtls.NewKeyPeerVerifier(roots, p.InstallationID, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	admission := &nativePodIdleAdmission{bootstrap: bootstrap, client: client, verifier: verifier}
	var published atomic.Pointer[native.Handler]
	channel, serverRoot := podWorkerTLSChannel(t, ctx, image, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { published.Load().ServeHTTP(w, r) }), roots)
	address, err := url.Parse(channel.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := native.NewHandler(contracts.NativeWorkerPath, address.Host, admission, 1)
	if err != nil {
		t.Fatal(err)
	}
	published.Store(handler)
	// No object/key operation is admitted in this fixture. The explicit synthetic
	// credentials must nonetheless be mounted and accepted by the actual command.
	private, err := json.Marshal(contracts.WorkerStoreCredentials{AccessKeyID: "synthetic-unused", SecretAccessKey: "synthetic-unused-secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	yes := true
	secret, err := admin.CoreV1().Secrets(namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "native-store"}, Immutable: &yes, Type: core.SecretTypeOpaque, Data: map[string][]byte{"credentials.json": private}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p.StoreCredentialSecret, p.StoreCredentialSecretUID = secret.Name, string(secret.UID)
	p.MemoryBytes = 64 << 20
	wire.Format = contracts.WorkerNativeControlFormat
	wire.Native = &contracts.WorkerNativeControl{Format: contracts.WorkerNativeStartupFormat, ExchangeEndpoint: channel.URL + contracts.NativeWorkerPath, ExchangeServerRoots: [][]byte{serverRoot}, ObjectStore: contracts.WorkerNativeStore{ID: custodyID(), Endpoint: bootstrap.endpoint, Region: "us-east-1", Bucket: "synthetic-unused", ServerRoots: [][]byte{bootstrap.serverRoot}, CredentialSecretName: secret.Name, CredentialSecretUID: string(secret.UID)}, KeyService: contracts.WorkerNativeKeyService{Endpoint: bootstrap.endpoint, ServerRoots: [][]byte{bootstrap.serverRoot}, Scope: contracts.KeyScope{InstallationID: p.InstallationID, Purpose: "artifact", KeyID: "synthetic-artifact"}}}
	return admission
}
