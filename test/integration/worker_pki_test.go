package integration

import (
	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	workertransport "asservat.local/asservat/internal/transport/worker"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func (f fixtureWorkerIdentity) ReadDownloadWorkerEnrollment(ctx context.Context, session, worker string) (value.DownloadWorkerIdentity, error) {
	if f.worker.Intent.SessionID != session || f.worker.Intent.ID != worker {
		return value.DownloadWorkerIdentity{}, artifact.ErrInvalid
	}
	return f.ReadDownloadWorkerIdentity(ctx, session, value.KeyPeer{})
}

// The compiled credential-phase executable runs in the admitted restricted Pod.
// Registry, issuance permit and audit are fixture inputs; real TokenReview,
// protected profile, TLS/CSR, OpenBao signing and process startup are exercised.
type ownedWorkerBootstrap struct {
	exchange               *actualWorkerEnrollmentExchange
	endpoint               string
	serverRoot, issuerRoot []byte
	checkIssuer            func(context.Context)
}

func preparePodWorkerBootstrap(t *testing.T, ctx context.Context, f fixture, c *kube.PermissionClient, localImage string, profile value.DownloadWorkerProfile, recoveryEpoch string) *ownedWorkerBootstrap {
	t.Helper()
	mount := "worker-pki-" + profile.InstallationID
	signer := "worker-signer-" + profile.InstallationID
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+mount, map[string]any{"type": "pki"}, 204)
	root := request(t, f.KMS, "synthetic-root", mount+"/root/generate/internal", map[string]any{"common_name": "synthetic-worker-root", "ttl": "1h", "key_type": "ec", "key_bits": 256}, 200)
	roots := x509.NewCertPool()
	rootPEM := []byte(root["data"].(map[string]any)["certificate"].(string))
	block, _ := pem.Decode(rootPEM)
	if block == nil || !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("invalid worker root")
	}
	role := map[string]any{"require_cn": false, "use_csr_common_name": false, "use_csr_sans": false, "allow_ip_sans": false, "allowed_uri_sans": []string{"spiffe://asservat." + profile.InstallationID + "/key-client/acquisition/*"}, "key_type": "any", "server_flag": false, "client_flag": true, "code_signing_flag": false, "email_protection_flag": false, "key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{}, "basic_constraints_valid_for_non_ca": true, "not_before_duration": "30s", "max_ttl": "1h"}
	request(t, f.KMS, "synthetic-root", mount+"/roles/acquisition", role, 200)
	request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+signer, map[string]any{"policy": `path "` + mount + `/sign/acquisition" { capabilities=["update"] }`}, 204)
	token := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{signer}, "no_default_policy": true, "ttl": "15m"}, 200)["auth"].(map[string]any)["client_token"].(string)
	bridge := tlsBridge(t, f.KMS)
	issuer, e := kms.NewWorkerCertificateIssuer(bridge.URL, token, mount, "acquisition", profile.InstallationID, recoveryEpoch, roots, bridge.Client(), time.Now)
	if e != nil {
		t.Fatal(e)
	}
	exchange := &actualWorkerEnrollmentExchange{client: c, issuer: issuer}
	handler, e := workertransport.NewHandler(profile.InstallationID, exchange, time.Now, 1)
	if e != nil {
		t.Fatal(e)
	}
	channel, serverRoot := podWorkerChannel(t, ctx, localImage, handler)
	out := &ownedWorkerBootstrap{exchange: exchange, endpoint: channel.URL, serverRoot: serverRoot, issuerRoot: bytes.Clone(block.Bytes)}
	out.checkIssuer = func(ctx context.Context) {
		exchange.mu.Lock()
		attempt, csr, issued := exchange.attempt, bytes.Clone(exchange.csr), exchange.issued
		exchange.mu.Unlock()
		if !attempt.Matches(issued) {
			t.Fatal("compiled worker did not enroll")
		}
		wrong := attempt
		wrong.Enrollment.PublicKeyDigest[0]++
		if _, e := issuer.SignWorkerCertificate(ctx, wrong, csr); e == nil {
			t.Fatal("foreign CSR key accepted")
		}
		wrong = attempt
		wrong.RecoveryEpoch = custodyID()
		if _, e := issuer.SignWorkerCertificate(ctx, wrong, csr); e == nil {
			t.Fatal("foreign issuer epoch accepted")
		}
		request(t, f.KMS, token, mount+"/roles/forbidden", role, 403)
		request(t, f.KMS, "synthetic-root", "auth/token/revoke", map[string]any{"token": token}, 204)
		if _, e := issuer.SignWorkerCertificate(ctx, attempt, csr); e == nil {
			t.Fatal("revoked signing credential accepted")
		}
	}
	return out
}

func (b *ownedWorkerBootstrap) bind(w value.DownloadWorker, configuration evidence.WorkerConfigurationGuard) {
	b.exchange.mu.Lock()
	defer b.exchange.mu.Unlock()
	b.exchange.worker, b.exchange.configuration = w, configuration
}

// A fixture-only owned container forwards encrypted TCP to this Unix socket.
// No host port/firewall change, plaintext hop, wildcard host listener or authority
// bypass is needed. The proxy owns no credentials and bounds concurrent copies.
func podWorkerChannel(t *testing.T, ctx context.Context, localImage string, handler http.Handler) (*httptest.Server, []byte) {
	return podWorkerTLSChannel(t, ctx, localImage, handler, nil)
}

func podWorkerTLSChannel(t *testing.T, ctx context.Context, localImage string, handler http.Handler, clientRoots *x509.CertPool) (*httptest.Server, []byte) {
	t.Helper()
	directory, err := os.MkdirTemp("", "wc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(directory, "s")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	if err = os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	} // parent remains private 0700
	name := "asservat-worker-channel-" + custodyID()
	// The relay must share the kind nodes' Docker network. The harness puts
	// them on its own per-run network; plain kind uses the shared "kind".
	network := os.Getenv("KIND_EXPERIMENTAL_DOCKER_NETWORK")
	if network == "" {
		network = "kind"
	}
	command := func(args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, "docker", args...).Output()
		if err != nil {
			t.Fatalf("owned TLS relay command failed: %v", err)
		}
		return out
	}
	command("create", "--name", name, "--label", "asservat.test=worker-channel-fixture", "--network", network, "--user", "65532:65532", "--read-only", "--memory", "64m", "--cpus", "0.25", "--pids-limit", "64", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", "type=bind,src="+path+",dst=/channel.sock", "--entrypoint", "/fixture", localImage, "fixture-proxy")
	t.Cleanup(func() {
		cleanup, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		if err := exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run(); err != nil {
			t.Error("owned TLS relay cleanup", err)
		}
	})
	command("start", name)
	raw := command("inspect", "--format", "{{json .NetworkSettings.Networks}}", name)
	var networks map[string]struct{ IPAddress string }
	if json.Unmarshal(raw, &networks) != nil {
		t.Fatal("invalid relay network")
	}
	ip := net.ParseIP(networks[network].IPAddress)
	if ip == nil || ip.IsUnspecified() {
		t.Fatal("missing owned relay address")
	}
	root := newWorkerChannelFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(100), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{ip}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, root.root, key.Public(), root.key)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener.Close()
	server.Listener = listener
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der, root.root.Raw}, PrivateKey: key}}}
	if clientRoots != nil {
		server.EnableHTTP2 = true
		server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		server.TLS.ClientCAs = clientRoots.Clone()
	}
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.ReadTimeout = 30 * time.Second
	server.Config.WriteTimeout = 30 * time.Second
	server.Config.IdleTimeout = 2 * time.Second
	server.Config.MaxHeaderBytes = 20 << 10
	server.StartTLS()
	server.URL = "https://" + net.JoinHostPort(ip.String(), "8443")
	t.Cleanup(server.Close)
	return server, root.root.Raw
}

// This fixture replaces only the durable issuance coordinator, not token review,
// CSR validation, PKI client, transport or the worker credential implementation.
type actualWorkerEnrollmentExchange struct {
	mu            sync.Mutex
	stage         atomic.Int64 // Test-only failure location; never records tokens/CSRs.
	client        *kube.PermissionClient
	worker        value.DownloadWorker
	configuration evidence.WorkerConfigurationGuard
	issuer        evidence.WorkerCertificateIssuer
	attempt       value.WorkerCertificateAttempt
	csr           []byte
	issued        value.WorkerCertificate
}
type receivedWorkerToken []byte

func (t receivedWorkerToken) ReadDownloadPeerToken(ctx context.Context) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return bytes.Clone(t), nil
}
func (s *actualWorkerEnrollmentExchange) EnrollWorker(ctx context.Context, installation, session, worker string, token, csr []byte) (value.WorkerCertificate, error) {
	var zero value.WorkerCertificate
	s.stage.Store(1)
	s.mu.Lock()
	w, configuration := s.worker, s.configuration
	s.mu.Unlock()
	s.stage.Store(2)
	if !w.Valid() || configuration == nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	s.stage.Store(3)
	if installation != w.Binding.InstallationID || session != w.Intent.SessionID || worker != w.Intent.ID {
		return zero, artifact.ErrInvalid
	}
	s.stage.Store(4)
	key, e := mtls.EnrollmentKey(csr)
	if e != nil {
		return zero, e
	}
	s.stage.Store(5)
	source, e := kube.NewWorkerEnrollmentAttester(s.client, fixtureWorkerIdentity{w, configuration}, receivedWorkerToken(token))
	if e != nil {
		return zero, e
	}
	s.stage.Store(6)
	proof, e := source.ReadWorkerEnrollmentProof(ctx, session, worker, key)
	if e != nil || proof.Worker != w {
		return zero, artifact.ErrDownloadUnavailable
	}
	s.stage.Store(7)
	now := time.Now().UTC()
	epoch, until, e := value.WorkerCertificateEpoch(w, now)
	if e != nil {
		return zero, e
	}
	attempt := value.WorkerCertificateAttempt{ID: custodyID(), Epoch: epoch, Ordinal: 1, Enrollment: value.WorkerEnrollment{Worker: w, PublicKeyDigest: key, ClaimedAt: now}, Proof: proof, RecoveryEpoch: w.Intent.Authority.Environment.RecoveryEpoch, EnrollmentAudit: artifact.Digest{17}, CheckedAt: now, SignBefore: proof.FreshUntil, CertificateNotAfter: until}
	s.stage.Store(8)
	issued, e := s.issuer.SignWorkerCertificate(ctx, attempt, csr)
	if e != nil || !attempt.Matches(issued) {
		return zero, artifact.ErrDownloadUnavailable
	}
	s.mu.Lock()
	s.attempt, s.csr, s.issued = attempt, bytes.Clone(csr), issued
	s.mu.Unlock()
	s.stage.Store(9)
	return issued, nil
}
